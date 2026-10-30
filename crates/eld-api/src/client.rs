//! Minimal HTTP/1.1 client over the eld Unix socket. One request per
//! connection; the daemon always answers with `Connection: close`.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// A decoded response.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Client for one socket path.
#[derive(Debug, Clone)]
pub struct Client {
    pub socket: PathBuf,
}

impl Client {
    pub fn new(socket: impl AsRef<Path>) -> Self {
        Client { socket: socket.as_ref().to_path_buf() }
    }

    fn send(&self, method: &str, path: &str, headers: &[(&str, &str)], body: Option<&[u8]>) -> io::Result<UnixStream> {
        let mut s = UnixStream::connect(&self.socket)?;
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: eld\r\nConnection: close\r\n");
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some(b) = body {
            req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes())?;
        if let Some(b) = body {
            s.write_all(b)?;
        }
        Ok(s)
    }

    /// Sends a request and reads the whole response.
    pub fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> io::Result<Response> {
        let s = self.send(method, path, headers, body)?;
        let mut r = BufReader::new(s);
        let (status, headers) = read_head(&mut r)?;
        let mut body = Vec::new();
        r.read_to_end(&mut body)?;
        Ok(Response { status, headers, body })
    }

    /// Opens a Server-Sent Events stream and calls `on_data` for each
    /// `data:` payload until the stream ends or `on_data` returns false.
    pub fn stream(&self, path: &str, mut on_data: impl FnMut(&str) -> bool) -> io::Result<u16> {
        let s = self.send("GET", path, &[("Accept", "text/event-stream")], None)?;
        let mut r = BufReader::new(s);
        let (status, _) = read_head(&mut r)?;
        if status != 200 {
            return Ok(status);
        }
        let mut line = String::new();
        loop {
            line.clear();
            if r.read_line(&mut line)? == 0 {
                return Ok(status);
            }
            if let Some(data) = line.trim_end().strip_prefix("data: ") {
                if !on_data(data) {
                    return Ok(status);
                }
            }
        }
    }
}

fn read_head(r: &mut impl BufRead) -> io::Result<(u16, Vec<(String, String)>)> {
    let mut line = String::new();
    r.read_line(&mut line)?;
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad status line"))?;
    let mut headers = Vec::new();
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            break;
        }
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, headers))
}
