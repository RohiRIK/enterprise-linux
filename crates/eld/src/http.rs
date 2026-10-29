//! A deliberately small HTTP/1.1 server codec for the local Unix socket:
//! one request per connection, `Content-Length` bodies only, strict limits.

use eld_api::ApiError;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{self, BufRead, Read, Write};

const MAX_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 64;
/// Largest accepted request body (a policy document is a few KiB).
pub const MAX_BODY: usize = 1024 * 1024;

/// A parsed request.
#[derive(Debug, Default)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// Whether a query flag is set to a true value.
    pub fn flag(&self, name: &str) -> bool {
        matches!(self.query.get(name).map(String::as_str), Some("1" | "true" | "yes" | ""))
    }
}

/// A response to write.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json<T: Serialize + ?Sized>(status: u16, v: &T) -> Response {
        let mut body = serde_json::to_vec_pretty(v).unwrap_or_default();
        body.push(b'\n');
        Response { status, headers: vec![("Content-Type".into(), "application/json".into())], body }
    }

    pub fn error(status: u16, code: &str, message: impl Into<String>) -> Response {
        Response::json(status, &ApiError { code: code.into(), message: message.into() })
    }

    pub fn with_header(mut self, k: &str, v: &str) -> Response {
        self.headers.push((k.into(), v.into()));
        self
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// Writes a complete response and closes the exchange.
pub fn write_response(w: &mut impl Write, r: &Response) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        r.status,
        reason(r.status),
        r.body.len()
    );
    for (k, v) in &r.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    w.write_all(head.as_bytes())?;
    w.write_all(&r.body)?;
    w.flush()
}

/// Writes the head of a Server-Sent Events stream.
pub fn write_sse_head(w: &mut impl Write) -> io::Result<()> {
    w.write_all(
        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n",
    )?;
    w.flush()
}

fn read_line(r: &mut impl BufRead) -> Result<String, Response> {
    let mut buf = Vec::new();
    let n = r
        .by_ref()
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut buf)
        .map_err(|e| Response::error(400, eld_api::code::BAD_REQUEST, e.to_string()))?;
    if n > MAX_LINE {
        return Err(Response::error(431, eld_api::code::BAD_REQUEST, "line too long"));
    }
    String::from_utf8(buf)
        .map(|s| s.trim_end_matches(['\r', '\n']).to_string())
        .map_err(|_| Response::error(400, eld_api::code::BAD_REQUEST, "request is not UTF-8"))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                match std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()).ok_or(())
                {
                    Ok(v) => {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads one request. On a protocol error returns the response to send.
pub fn read_request(r: &mut impl BufRead) -> Result<Request, Response> {
    let line = read_line(r)?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Response::error(400, eld_api::code::BAD_REQUEST, "malformed request line"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(Response::error(400, eld_api::code::BAD_REQUEST, "only HTTP/1.x is supported"));
    }
    let (path, qs) = target.split_once('?').unwrap_or((target, ""));
    let mut req = Request { method: method.to_string(), path: percent_decode(path), ..Default::default() };
    for pair in qs.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        req.query.insert(percent_decode(k), percent_decode(v));
    }
    loop {
        let h = read_line(r)?;
        if h.is_empty() {
            break;
        }
        if req.headers.len() == MAX_HEADERS {
            return Err(Response::error(431, eld_api::code::BAD_REQUEST, "too many headers"));
        }
        let Some((k, v)) = h.split_once(':') else {
            return Err(Response::error(400, eld_api::code::BAD_REQUEST, "malformed header"));
        };
        req.headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    if req.header("Transfer-Encoding").is_some() {
        return Err(Response::error(
            411,
            eld_api::code::BAD_REQUEST,
            "chunked bodies are not supported; send Content-Length",
        ));
    }
    if let Some(len) = req.header("Content-Length") {
        let len: usize =
            len.parse().map_err(|_| Response::error(400, eld_api::code::BAD_REQUEST, "bad Content-Length"))?;
        if len > MAX_BODY {
            return Err(Response::error(413, eld_api::code::BAD_REQUEST, "body too large"));
        }
        req.body = vec![0; len];
        r.read_exact(&mut req.body).map_err(|e| Response::error(400, eld_api::code::BAD_REQUEST, e.to_string()))?;
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    #[test]
    fn parses_request() {
        let raw = b"PUT /v1/settings?dryRun=1&x=a%20b HTTP/1.1\r\nHost: eld\r\nIf-Match: \"r1\"\r\nContent-Length: 2\r\n\r\n{}";
        let req = read_request(&mut BufReader::new(&raw[..])).unwrap();
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/v1/settings");
        assert!(req.flag("dryRun"));
        assert_eq!(req.query["x"], "a b");
        assert_eq!(req.header("if-match"), Some("\"r1\""));
        assert_eq!(req.body, b"{}");
    }

    #[test]
    fn rejects_bad_input() {
        let big = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert_eq!(read_request(&mut BufReader::new(big.as_bytes())).unwrap_err().status, 413);
        let chunked = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(read_request(&mut BufReader::new(&chunked[..])).unwrap_err().status, 411);
        assert_eq!(read_request(&mut BufReader::new(&b"GARBAGE\r\n\r\n"[..])).unwrap_err().status, 400);
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
    }
}
