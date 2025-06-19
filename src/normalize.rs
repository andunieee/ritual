use url::Url;

use crate::Result;

/// normalize a URL and replace http://, https:// schemes with ws://, wss://
pub fn normalize_url(url_str: &str) -> Result<Url> {
    // try to parse the URL
    let mut url = match Url::parse(url_str) {
        Ok(url) => url,
        Err(_) => {
            // Handle cases like "localhost:1234"
            let with_scheme = if url_str.contains("localhost") || url_str.starts_with("127.0.0.1") {
                format!("ws://{}", url_str)
            } else {
                format!("wss://{}", url_str)
            };
            Url::parse(&with_scheme)?
        }
    };

    // normalize the scheme
    match url.scheme() {
        "https" => url.set_scheme("wss").unwrap(),
        "http" => url.set_scheme("ws").unwrap(),
        "ws" | "wss" => {} // already correct
        _ if url.host_str() == Some("localhost") => url.set_scheme("ws").unwrap(),
        _ if url.host_str() == Some("127.0.0.1") => url.set_scheme("ws").unwrap(),
        _ => url.set_scheme("wss").unwrap(),
    }

    // normalize host to lowercase
    if let Some(host) = url.host_str() {
        let _ = url.set_host(Some(&host.to_lowercase()));
    }

    // remove trailing slash from path
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);

    Ok(url)
}

/// normalize HTTP(S) URLs according to RFC3986
pub fn normalize_http_url(url_str: &str) -> Result<String> {
    let url_str = url_str.trim();

    let url_str = if !url_str.starts_with("http") {
        format!("https://{}", url_str)
    } else {
        url_str.to_string()
    };

    let mut url = Url::parse(&url_str)?;

    // remove default ports
    if let Some(port) = url.port() {
        let default_port = match url.scheme() {
            "http" => 80,
            "https" => 443,
            _ => 0,
        };
        if port == default_port {
            let _ = url.set_port(None);
        }
    }

    // remove trailing slash
    let mut url_string = url.to_string();
    if url_string.ends_with('/') && url.path() == "/" {
        url_string.pop();
    }

    Ok(url_string)
}

/// normalize OK message with prefix
pub fn normalize_ok_message(reason: &str, prefix: &str) -> String {
    if let Some(colon_pos) = reason.find(": ") {
        let before_colon = &reason[..colon_pos];
        if !before_colon.contains(' ') {
            return reason.to_string();
        }
    }
    format!("{}: {}", prefix, reason)
}
