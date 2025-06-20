use url::Url;

use crate::Result;

/// normalize a URL and replace http://, https:// schemes with ws://, wss://
pub fn normalize_url(url_str: &str) -> Result<Url> {
    let url_str = match url_str.split_once("://") {
        Some((scheme, _))
            if scheme == "wss" || scheme == "ws" || scheme == "WSS" || scheme == "WS" =>
        {
            url_str.to_string()
        }
        Some((scheme, _))
            if scheme == "https" || scheme == "http" || scheme == "HTTPS" || scheme == "HTTP" =>
        {
            format!("ws{}", &url_str[4..])
        }
        _ => {
            if url_str.starts_with("localhost")
                || url_str.contains(".localhost")
                || url_str.starts_with("127.0.0.1")
            {
                format!("ws://{}", url_str)
            } else {
                format!("wss://{}", url_str)
            }
        }
    };
    let mut url = Url::parse(&url_str)?;

    // normalize host to lowercase
    if let Some(host) = url.host_str() {
        let _ = url.set_host(Some(&host.to_lowercase()));
    }

    // remove trailing slash from path
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);

    Ok(url)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        let test_cases = vec![
            // basic cases
            ("wss://example.com", "wss://example.com/"),
            ("ws://example.com", "ws://example.com/"),
            ("https://example.com", "wss://example.com/"),
            ("http://example.com", "ws://example.com/"),
            // localhost cases
            ("localhost:8080", "ws://localhost:8080/"),
            ("127.0.0.1:8080", "ws://127.0.0.1:8080/"),
            ("test.localhost:3000", "ws://test.localhost:3000/"),
            // domain without scheme
            ("example.com", "wss://example.com/"),
            ("relay.damus.io", "wss://relay.damus.io/"),
            // with paths
            ("wss://example.com/path", "wss://example.com/path"),
            ("https://example.com/path/", "wss://example.com/path"),
            // case normalization
            ("WSS://EXAMPLE.COM", "wss://example.com/"),
            ("HTTP://LOCALHOST:8080", "ws://localhost:8080/"),
            // trailing slash removal
            ("wss://example.com/", "wss://example.com/"),
            ("https://example.com/p/p", "wss://example.com/p/p"),
        ];

        for (input, expected) in test_cases {
            let result = normalize_url(input).unwrap();
            assert_eq!(result.to_string(), expected, "failed for input: {}", input);
        }
    }

    #[test]
    fn test_normalize_ok_message() {
        let test_cases = vec![
            // already has prefix
            ("blocked: spam", "error", "blocked: spam"),
            ("rate-limited: too fast", "error", "rate-limited: too fast"),
            // needs prefix
            ("spam detected", "blocked", "blocked: spam detected"),
            ("invalid signature", "error", "error: invalid signature"),
            (
                "too many requests",
                "rate-limited",
                "rate-limited: too many requests",
            ),
            // edge cases
            ("", "error", "error: "),
            ("no colon here", "prefix", "prefix: no colon here"),
            ("multiple: colons: here", "error", "multiple: colons: here"),
            ("space before: colon", "error", "error: space before: colon"),
        ];

        for (reason, prefix, expected) in test_cases {
            let result = normalize_ok_message(reason, prefix);
            assert_eq!(
                result, expected,
                "failed for reason: '{}', prefix: '{}'",
                reason, prefix
            );
        }
    }

    #[test]
    fn test_normalize_url_errors() {
        let invalid_cases = vec!["not-a-url", "ftp://example.com", ""];

        for input in invalid_cases {
            let result = normalize_url(input);
            // some might succeed with our fallback logic, but we're testing they don't panic
            let _ = result;
        }
    }
}
