//! Human and YAML renderings of API responses.

use serde_json::Value;

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".into(),
        other => other.to_string(),
    }
}

fn flatten(prefix: &str, v: &Value, out: &mut Vec<(String, String)>) {
    match v {
        Value::Object(m) if !m.is_empty() => {
            for (k, x) in m {
                let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten(&key, x, out);
            }
        }
        Value::Array(a) if a.iter().any(|x| x.is_object()) => {
            for (i, x) in a.iter().enumerate() {
                flatten(&format!("{prefix}[{i}]"), x, out);
            }
        }
        Value::Array(a) => out.push((prefix.into(), a.iter().map(scalar).collect::<Vec<_>>().join(", "))),
        other => out.push((prefix.into(), scalar(other))),
    }
}

fn table(rows: &[(String, String)]) -> String {
    let w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    rows.iter().map(|(k, v)| format!("{k:w$}  {v}\n")).collect()
}

/// `key  value` lines for nested facts.
pub fn facts(v: &Value) -> String {
    let mut rows = vec![];
    flatten("", v, &mut rows);
    table(&rows)
}

/// Generic nested rendering.
pub fn value(v: &Value) -> String {
    facts(v)
}

pub fn settings(v: &Value) -> String {
    let mut s = String::new();
    if let Some(p) = v.get("policy").filter(|p| !p.is_null()) {
        s.push_str(&format!(
            "policy: {} {} ({}, {})\n",
            scalar(&p["name"]),
            scalar(&p["version"]),
            scalar(&p["status"]),
            scalar(&p["appliedAt"])
        ));
    }
    s.push_str(&format!("etag:   {}\n\n", scalar(&v["etag"])));
    let rows: Vec<(String, String)> = v["values"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|x| (scalar(&x["key"]), format!("{}  [{}]", scalar(&x["value"]), scalar(&x["source"]))))
        .collect();
    if rows.is_empty() {
        s.push_str("(no settings stored)\n");
    }
    s + &table(&rows)
}

pub fn apply(v: &Value) -> String {
    let mut s = String::new();
    if v["dryRun"] == Value::Bool(true) {
        s.push_str("dry run, nothing changed\n");
    }
    let rows: Vec<(String, String)> = v["results"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            let mut d = scalar(&r["key"]);
            match (r.get("old"), r.get("new")) {
                (Some(o), Some(n)) => d.push_str(&format!("  {} -> {}", scalar(o), scalar(n))),
                (None, Some(n)) => d.push_str(&format!("  {}", scalar(n))),
                _ => {}
            }
            if let Some(reason) = r.get("reason") {
                d.push_str(&format!("  ({})", scalar(reason)));
            }
            (scalar(&r["result"]), d)
        })
        .collect();
    s + &table(&rows)
}

pub fn actions(v: &Value) -> String {
    let rows: Vec<(String, String)> = v
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| {
            let mut d = format!("[{}]", scalar(&a["minRole"]));
            if a["implemented"] == Value::Bool(false) {
                d.push_str(" (not implemented)");
            }
            if a["destructive"] == Value::Bool(true) {
                d.push_str(" (destructive)");
            }
            d.push_str(&format!("  {}", scalar(&a["description"])));
            (scalar(&a["name"]), d)
        })
        .collect();
    table(&rows)
}

pub fn action(v: &Value) -> String {
    let mut s = format!("{}: {}\n", scalar(&v["action"]), scalar(&v["status"]));
    if let Some(m) = v.get("message") {
        s.push_str(&format!("{}\n", scalar(m)));
    }
    for c in v["commands"].as_array().into_iter().flatten() {
        let line: Vec<String> = c.as_array().into_iter().flatten().map(scalar).collect();
        s.push_str(&format!("  $ {}\n", line.join(" ")));
    }
    if let Some(d) = v.get("data") {
        s.push_str(&facts(d));
    }
    s
}

pub fn events(v: &Value) -> String {
    v.as_array()
        .into_iter()
        .flatten()
        .map(|e| {
            let who = e["actor"].get("user").map(scalar).unwrap_or_default();
            format!(
                "{} #{} {} [{}] {} {}\n",
                scalar(&e["time"]),
                scalar(&e["id"]),
                scalar(&e["type"]),
                scalar(&e["severity"]),
                who,
                e.get("data").map(|d| d.to_string()).unwrap_or_default()
            )
        })
        .collect()
}

pub fn whoami(v: &Value) -> String {
    let roles: Vec<String> = v["roles"].as_array().into_iter().flatten().map(scalar).collect();
    let mut s = format!(
        "user:   {} (uid {})\nroles:  {}\nsource: {}\n",
        scalar(&v["user"]),
        scalar(&v["uid"]),
        roles.join(", "),
        scalar(&v["source"])
    );
    if let Some(p) = v.get("principal") {
        s.push_str(&format!("principal: {}\n", scalar(p)));
    }
    s
}

fn yaml_str(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-/@+".contains(c))
        && !matches!(s, "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "~")
        && s.parse::<f64>().is_err();
    if plain {
        s.into()
    } else {
        serde_json::to_string(s).unwrap_or_default()
    }
}

fn yaml_into(v: &Value, indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    match v {
        Value::Object(m) if !m.is_empty() => {
            for (k, x) in m {
                match x {
                    Value::Object(sub) if !sub.is_empty() => {
                        out.push_str(&format!("{pad}{}:\n", yaml_str(k)));
                        yaml_into(x, indent + 2, out);
                    }
                    Value::Array(a) if !a.is_empty() => {
                        out.push_str(&format!("{pad}{}:\n", yaml_str(k)));
                        yaml_into(x, indent, out);
                    }
                    _ => out.push_str(&format!("{pad}{}: {}\n", yaml_str(k), yaml_scalar(x))),
                }
            }
        }
        Value::Array(a) if !a.is_empty() => {
            for x in a {
                match x {
                    Value::Object(sub) if !sub.is_empty() => {
                        let mut inner = String::new();
                        yaml_into(x, indent + 2, &mut inner);
                        out.push_str(&format!("{pad}- {}", &inner[indent + 2..]));
                    }
                    Value::Array(sub) if !sub.is_empty() => {
                        out.push_str(&format!("{pad}-\n"));
                        yaml_into(x, indent + 2, out);
                    }
                    _ => out.push_str(&format!("{pad}- {}\n", yaml_scalar(x))),
                }
            }
        }
        other => out.push_str(&format!("{pad}{}\n", yaml_scalar(other))),
    }
}

fn yaml_scalar(v: &Value) -> String {
    match v {
        Value::String(s) => yaml_str(s),
        Value::Object(_) => "{}".into(),
        Value::Array(_) => "[]".into(),
        other => other.to_string(),
    }
}

/// Renders a JSON value as block YAML.
pub fn yaml(v: &Value) -> String {
    let mut s = String::new();
    yaml_into(v, 0, &mut s);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn yaml_output() {
        let v = json!({"a": {"b": true, "c": ["x", "1"]}, "d": [{"e": 1, "f": "two words"}], "g": {}});
        assert_eq!(yaml(&v), "a:\n  b: true\n  c:\n  - x\n  - \"1\"\nd:\n- e: 1\n  f: \"two words\"\ng: {}\n");
    }

    #[test]
    fn facts_table() {
        let v = json!({"root": {"status": "encrypted"}, "dns": ["1.1.1.1", "9.9.9.9"]});
        assert_eq!(facts(&v), "dns          1.1.1.1, 9.9.9.9\nroot.status  encrypted\n");
    }
}
