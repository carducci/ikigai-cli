//! An error a browser asked for as a page (ledger #117).
//!
//! Every refusal this door writes is a sentence. A client that names `text/html` in `Accept`
//! (a browser navigating) and prefers it to `text/plain` gets that sentence as a minimal,
//! accessible HTML page; anything else (curl's `*/*`, a script asking for JSON, no `Accept`
//! at all) gets it as `text/plain`, exactly as before. The status is the same either way.
use crate::{bare_media, match_of, parse_accept, MatchedBy, Resp};

/// Answer `resp` as the client asked, when it is an error whose body is a plain sentence:
/// rewritten as a page for a client that asks for HTML, and in either case marked `Vary:
/// Accept`, because the body now depends on it (a `404` is cacheable by default, RFC 9110
/// §15.1). Any other answer, including a JSON error body a door chose, is left alone.
pub(crate) fn negotiate(mut resp: Resp, accept: Option<&str>) -> Resp {
    if resp.status < 400 || bare_media(&resp.content_type) != "text/plain" {
        return resp;
    }
    resp.add_vary("Accept");
    if wants_html(accept) {
        let message = String::from_utf8_lossy(&resp.body).into_owned();
        resp.body = page(resp.status, resp.reason, &message).into_bytes();
        resp.content_type = "text/html; charset=utf-8".to_string();
    }
    resp
}

/// Whether `Accept` asks for HTML over plain text: `text/html` NAMED (a wildcard tolerates
/// HTML without asking for it, and is what curl sends), at a quality above zero and above
/// `text/plain`'s. A tie stays plain, the answer this door gave before pages existed.
fn wants_html(accept: Option<&str>) -> bool {
    let Some(accept) = accept else {
        return false;
    };
    let ranges = parse_accept(accept);
    let Some(html) = match_of("text/html", &ranges) else {
        return false;
    };
    let plain = match_of("text/plain", &ranges).map_or(0.0, |m| m.q);
    html.by == MatchedBy::Name && html.q > 0.0 && html.q > plain
}

/// The page: a language, a title, a `main` landmark, a heading naming the status, and the
/// message, escaped. No style and no script, so the strict default CSP has nothing to block.
///
/// ```text
/// <!DOCTYPE html>
/// <html lang="en">
/// <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>404 Not Found</title></head>
/// <body><main><h1>404 Not Found</h1><p>no route</p></main></body>
/// </html>
/// ```
pub(crate) fn page(status: u16, reason: &str, message: &str) -> String {
    let title = escape(format!("{status} {reason}").trim());
    let message = message.trim();
    let paragraph = if message.is_empty() {
        String::new()
    } else {
        format!("<p>{}</p>", escape(message))
    };
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title></head>\n<body><main><h1>{title}</h1>{paragraph}</main></body>\n</html>\n"
    )
}

/// Escape text for an HTML element or attribute value.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_browser_gets_a_page_and_curl_does_not() {
        let browser = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        assert!(wants_html(Some(browser)));
        for other in [
            None,
            Some("*/*"),
            Some("application/json"),
            Some("text/*"),
            Some("text/plain, text/html"),
            Some("text/html;q=0"),
            Some("text/plain, text/html;q=0.5"),
        ] {
            assert!(!wants_html(other), "{other:?}");
        }
    }

    #[test]
    fn the_page_escapes_the_message_and_names_the_status() {
        let html = page(404, "Not Found", "no <script>alert('x')</script> & \"y\"");
        assert!(html.contains("<html lang=\"en\">"), "{html}");
        assert!(html.contains("<title>404 Not Found</title>"), "{html}");
        assert!(html.contains("<main><h1>404 Not Found</h1>"), "{html}");
        assert!(
            html.contains(
                "<p>no &lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;y&quot;</p>"
            ),
            "{html}"
        );
        assert!(!html.contains("<script>"), "{html}");
        // An empty sentence is a heading alone.
        assert!(!page(431, "Request Header Fields Too Large", "").contains("<p>"));
    }
}
