#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::env;
use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::time::Duration;

use reqwest::blocking::{Client, Response as UpstreamResponse};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::Method;
use tiny_http::{Header, Request, Response, Server};

const DEFAULT_SERVER_URL: &str = "https://10.248.55.161";
const DEFAULT_LOCAL_PORT: u16 = 18443;
const ROOT_CA: &[u8] = include_bytes!("../assets/root-ca.crt");
const MAX_BODY: u64 = 256 * 1024 * 1024;

struct Config {
    server_url: String,
    server_host: String,
    local_port: u16,
}

impl Config {
    fn load() -> Self {
        let mut server_url = DEFAULT_SERVER_URL.to_string();
        let mut local_port = DEFAULT_LOCAL_PORT;
        for path in config_paths() {
            if let Ok(text) = fs::read_to_string(path) {
                apply_config(&text, &mut server_url, &mut local_port);
                break;
            }
        }
        if let Ok(value) = env::var("FSTEC_SERVER_URL") {
            if !value.trim().is_empty() {
                server_url = value.trim().to_string();
            }
        }
        if let Ok(value) = env::var("FSTEC_LOCAL_PORT") {
            if let Ok(port) = value.trim().parse::<u16>() {
                local_port = port;
            }
        }
        server_url = server_url.trim_end_matches('/').to_string();
        let parsed = reqwest::Url::parse(&server_url).ok();
        let valid = parsed
            .as_ref()
            .map(|url| url.scheme() == "https" && url.host_str().is_some())
            .unwrap_or(false);
        if !valid {
            server_url = DEFAULT_SERVER_URL.to_string();
        }
        let server_host = reqwest::Url::parse(&server_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .unwrap_or_else(|| "10.248.55.161".to_string());
        if !(1024..=65535).contains(&local_port) {
            local_port = DEFAULT_LOCAL_PORT;
        }
        Self { server_url, server_host, local_port }
    }

    fn local_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.local_port)
    }
}

fn config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("fstec-client.conf"));
        }
    }
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    if let Some(home) = home {
        paths.push(home.join(".config/fstec-client/fstec-client.conf"));
    }
    paths
}

fn apply_config(text: &str, server_url: &mut String, local_port: &mut u16) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "server_url" => {
                let value = value.trim();
                if !value.is_empty() {
                    *server_url = value.to_string();
                }
            }
            "local_port" => {
                if let Ok(port) = value.trim().parse::<u16>() {
                    *local_port = port;
                }
            }
            _ => {}
        }
    }
}

fn main() {
    let config = Config::load();
    let cert = match reqwest::Certificate::from_pem(ROOT_CA) {
        Ok(cert) => cert,
        Err(_) => return,
    };
    let client = match Client::builder()
        .add_root_certificate(cert)
        .redirect(Policy::none())
        .timeout(Duration::from_secs(300))
        .build()
    {
        Ok(client) => client,
        Err(_) => return,
    };
    let address: SocketAddr = format!("127.0.0.1:{}", config.local_port)
        .parse()
        .expect("local address");
    let server = match Server::http(address) {
        Ok(server) => server,
        Err(_) => {
            open_browser(&config.local_url());
            return;
        }
    };
    let local_url = config.local_url();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        open_browser(&local_url);
    });
    for request in server.incoming_requests() {
        handle(request, &client, &config);
    }
}

fn open_browser(local_url: &str) {
    let url = format!("{local_url}/verify/");
    #[cfg(target_os = "linux")]
    {
        if let Ok(_) = Command::new("xdg-open").arg(&url).spawn() {
            return;
        }
        for command in ["firefox", "chromium", "chromium-browser", "google-chrome", "yandex-browser"] {
            if let Ok(_) = Command::new(command).arg(&url).spawn() {
                return;
            }
        }
    }
    let _ = open::that(url);
}

fn handle(mut request: Request, client: &Client, config: &Config) {
    let method = match Method::from_bytes(request.method().as_str().as_bytes()) {
        Ok(method) => method,
        Err(_) => {
            let _ = request.respond(Response::from_string("bad method").with_status_code(400));
            return;
        }
    };
    let mut headers = HeaderMap::new();
    for header in request.headers() {
        let name = header.field.as_str().as_str().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "host"
                | "content-length"
                | "connection"
                | "proxy-connection"
                | "transfer-encoding"
                | "accept-encoding"
        ) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(header.value.as_str()),
        ) {
            headers.append(name, value);
        }
    }
    if let Ok(value) = HeaderValue::from_str("identity") {
        headers.insert("accept-encoding", value);
    }
    let mut body = Vec::new();
    if request.as_reader().take(MAX_BODY).read_to_end(&mut body).is_err() {
        let _ = request.respond(Response::from_string("request read failed").with_status_code(400));
        return;
    }
    let target = format!("{}{}", config.server_url, request.url());
    let mut outgoing = client.request(method, target).headers(headers);
    if !body.is_empty() {
        outgoing = outgoing.body(body);
    }
    let upstream = match outgoing.send() {
        Ok(response) => response,
        Err(_) => {
            let _ = request.respond(
                Response::from_string("upstream unavailable").with_status_code(502),
            );
            return;
        }
    };
    respond(request, upstream, config);
}

fn respond(request: Request, upstream: UpstreamResponse, config: &Config) {
    let status = upstream.status().as_u16();
    let mut headers = Vec::new();
    for (name, value) in upstream.headers() {
        let name = name.as_str().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "content-length"
                | "connection"
                | "transfer-encoding"
                | "content-encoding"
                | "strict-transport-security"
                | "alt-svc"
        ) {
            continue;
        }
        let mut value = value.to_str().unwrap_or("").to_string();
        if name == "location" {
            if let Ok(mut location) = reqwest::Url::parse(&value) {
                if location.host_str() == Some(config.server_host.as_str()) {
                    let _ = location.set_scheme("http");
                    let _ = location.set_host(Some("127.0.0.1"));
                    let _ = location.set_port(Some(config.local_port));
                    value = location.to_string();
                }
            }
        }
        if let Ok(header) = Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            headers.push(header);
        }
    }
    let body = match upstream.bytes() {
        Ok(body) => body,
        Err(_) => {
            let _ = request.respond(
                Response::from_string("upstream read failed").with_status_code(502),
            );
            return;
        }
    };
    let mut response = Response::from_data(body).with_status_code(status);
    for header in headers {
        response.add_header(header);
    }
    let _ = request.respond(response);
}
