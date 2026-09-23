//! How a session travels between an API and its clients: two cookies for a
//! browser, or the tokens in the body for a native app ("header mode").
//!
//! Extracted from Gakuin's `auth::password`, which is the only writer of these
//! cookies there. The rules it settled are kept:
//!
//! * The cookies are `HttpOnly`, so no script can read them, and
//!   `SameSite=Lax`, which is what lets [`crate::CoreClient::create_session`]
//!   leave anti-CSRF off.
//! * `Secure` whenever the API is served over `https`.
//! * **Header mode is asked for by the exact word `header`** in
//!   [`AUTH_MODE_HEADER`], and on refresh it reads the refresh token from
//!   `Authorization` and **never** from the cookie. Falling back to the cookie
//!   would let script on the web app's origin turn one `fetch` with an extra
//!   header into a readable refresh token: the escalation `HttpOnly` exists to
//!   prevent.
//!
//! The cookie names are fixed. Two products whose cookies are scoped to the
//! same parent domain would overwrite each other's sessions, so never deploy
//! two of them under one [`cookie_domain`].

use axum::http::{header, HeaderMap, HeaderValue};

use crate::MintedSession;

/// The access token's cookie.
pub const ACCESS_COOKIE: &str = "sAccessToken";

/// The refresh token's cookie.
pub const REFRESH_COOKIE: &str = "sRefreshToken";

/// The request header a native client sends, with the value `header`, to get
/// its tokens in the response body instead of in cookies.
pub const AUTH_MODE_HEADER: &str = "st-auth-mode";

/// Where and how a deployment's session cookies are set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookiePolicy {
    domain: Option<String>,
    secure: bool,
}

impl CookiePolicy {
    /// The policy for an API at `api_url` serving a website at `website_url`.
    ///
    /// The domain comes from [`cookie_domain`]. `Secure` is set when the API is
    /// served over `https`.
    pub fn for_deployment(api_url: &str, website_url: &str) -> Self {
        Self {
            domain: cookie_domain(api_url, website_url),
            secure: api_url.starts_with("https://"),
        }
    }

    /// The `Domain=` the cookies carry, or `None` for host-only.
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Whether the cookies are `Secure`.
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// One `Set-Cookie` value. `max_age` of `None` makes a cookie that dies with
    /// the browser; `Some(0)` clears it.
    pub fn set_cookie(&self, name: &str, value: &str, max_age: Option<i64>) -> String {
        let mut cookie = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax");
        if let Some(domain) = &self.domain {
            cookie.push_str("; Domain=");
            cookie.push_str(domain);
        }
        if self.secure {
            cookie.push_str("; Secure");
        }
        if let Some(seconds) = max_age {
            cookie.push_str(&format!("; Max-Age={seconds}"));
        }
        cookie
    }

    /// Add a session's two cookies to a response's headers.
    ///
    /// # Errors
    ///
    /// When a token cannot be a header value. The core's tokens always can;
    /// the error exists so that a cookie is never dropped without saying so.
    pub fn append_session(
        &self,
        headers: &mut HeaderMap,
        session: &MintedSession,
    ) -> Result<(), header::InvalidHeaderValue> {
        self.append(
            headers,
            ACCESS_COOKIE,
            &session.access_token,
            max_age_seconds(session.access_expiry_ms),
        )?;
        self.append(
            headers,
            REFRESH_COOKIE,
            &session.refresh_token,
            max_age_seconds(session.refresh_expiry_ms),
        )
    }

    /// Add the two cookies that clear a session, for a sign-out. Sign-out
    /// should clear them whatever else fails: a sign-out that can fail is one
    /// somebody has to press twice.
    pub fn append_cleared(&self, headers: &mut HeaderMap) {
        for name in [ACCESS_COOKIE, REFRESH_COOKIE] {
            // An empty value and a policy's own domain always make a valid header.
            if let Ok(value) = HeaderValue::from_str(&self.set_cookie(name, "", Some(0))) {
                headers.append(header::SET_COOKIE, value);
            }
        }
    }

    fn append(
        &self,
        headers: &mut HeaderMap,
        name: &str,
        value: &str,
        max_age: Option<i64>,
    ) -> Result<(), header::InvalidHeaderValue> {
        let value = HeaderValue::from_str(&self.set_cookie(name, value, max_age))?;
        headers.append(header::SET_COOKIE, value);
        Ok(())
    }
}

/// The domain to scope session cookies to, or `None` for host-only.
///
/// An API and a website are usually two hosts, `api.example.org` and
/// `example.org`, and a host-only cookie the API sets never reaches the
/// website. So the cookie is scoped to the parent they share, and only when
/// they genuinely share one:
///
/// * the same host (`localhost` on two ports; ports are not part of a cookie's
///   identity) → `None`, which already reaches both;
/// * one a subdomain of the other, or two subdomains of one parent → the parent;
/// * unrelated hosts, IP addresses, or a shared suffix of one label (`edu`) →
///   `None`. Scoping to `edu` would hand the session to every university.
///
/// This does not consult the public suffix list. Two hosts under `co.uk` would
/// yield `co.uk`, which every browser refuses, so the sign-in would silently
/// not take. Deploy under a registrable domain.
pub fn cookie_domain(api_url: &str, website_url: &str) -> Option<String> {
    let api = host_of(api_url)?;
    let web = host_of(website_url)?;
    if api == web {
        return None;
    }
    if api.parse::<std::net::IpAddr>().is_ok() || !api.contains('.') {
        return None;
    }

    let mut shared: Vec<&str> = api
        .rsplit('.')
        .zip(web.rsplit('.'))
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a)
        .collect();
    if shared.len() < 2 {
        return None;
    }
    shared.reverse();
    Some(shared.join("."))
}

fn host_of(url: &str) -> Option<String> {
    let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = without_scheme
        .split('/')
        .next()?
        .split('@')
        .next_back()?
        .split(':')
        .next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Seconds from now until an absolute millisecond expiry, never negative. A
/// negative `Max-Age` is a cookie the browser keeps instead of dropping.
///
/// `None` when the clock cannot be read, which yields a cookie that dies with
/// the browser rather than one that never expires.
pub fn max_age_seconds(expiry_ms: i64) -> Option<i64> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis();
    let now_ms = i64::try_from(now_ms).ok()?;
    Some(((expiry_ms - now_ms) / 1000).max(0))
}

/// The value of one cookie on a request.
pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .find_map(|part| part.trim().strip_prefix(&prefix).map(ToOwned::to_owned))
        })
}

/// Whether the caller asked for its tokens in the body.
///
/// Only the word `header`, in any case and trimmed, turns it on. Anything
/// else (`cookie`, a typo, an empty value, bytes that are not UTF-8) stays on
/// cookies. The mistake that matters is sending tokens in a body to a caller
/// that did not mean to ask, so failing towards cookies is the safe direction.
pub fn wants_header_mode(headers: &HeaderMap) -> bool {
    headers
        .get(AUTH_MODE_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("header"))
}

/// The token in `Authorization: Bearer <token>`, or `None`.
///
/// Never `Some("")`: an empty token sent to the core as a refresh attempt is
/// answered with a 500 rather than a 401.
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
}

/// The refresh token for a refresh request: from `Authorization` in header
/// mode, from the cookie otherwise, and never the one when the caller asked
/// for the other. See the module header for why.
pub fn refresh_token(headers: &HeaderMap) -> Option<String> {
    if wants_header_mode(headers) {
        bearer_token(headers)
    } else {
        read_cookie(headers, REFRESH_COOKIE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderName;

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes()).expect("name should parse"),
                value.parse().expect("value should parse"),
            );
        }
        headers
    }

    #[test]
    fn one_host_on_two_ports_needs_no_domain() {
        assert_eq!(
            cookie_domain("http://localhost:5001", "http://localhost:5000"),
            None
        );
    }

    #[test]
    fn an_api_subdomain_scopes_to_the_parent() {
        assert_eq!(
            cookie_domain("https://api.northfield.edu", "https://northfield.edu").as_deref(),
            Some("northfield.edu")
        );
        assert_eq!(
            cookie_domain("https://api.zaisei.bjorst.com", "https://zaisei.bjorst.com").as_deref(),
            Some("zaisei.bjorst.com")
        );
    }

    #[test]
    fn a_shared_suffix_alone_is_not_a_shared_domain() {
        assert_eq!(
            cookie_domain("https://api.northfield.edu", "https://portal.southgate.edu"),
            None
        );
        assert_eq!(
            cookie_domain("https://api.example.com", "https://other.org"),
            None
        );
    }

    #[test]
    fn an_address_is_not_a_domain() {
        assert_eq!(
            cookie_domain("http://203.0.113.5:5001", "http://203.0.113.6:5000"),
            None
        );
    }

    #[test]
    fn the_policy_writes_every_attribute_it_holds() {
        let policy = CookiePolicy::for_deployment(
            "https://api.zaisei.bjorst.com",
            "https://zaisei.bjorst.com",
        );
        assert_eq!(
            policy.set_cookie(ACCESS_COOKIE, "tok", Some(60)),
            "sAccessToken=tok; Path=/; HttpOnly; SameSite=Lax; Domain=zaisei.bjorst.com; Secure; Max-Age=60"
        );
    }

    #[test]
    fn plain_http_is_not_secure_and_localhost_is_host_only() {
        let policy = CookiePolicy::for_deployment("http://localhost:5101", "http://localhost:3000");
        assert!(!policy.secure());
        assert_eq!(policy.domain(), None);
        assert_eq!(
            policy.set_cookie(REFRESH_COOKIE, "r", None),
            "sRefreshToken=r; Path=/; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn a_session_becomes_two_cookies_and_a_sign_out_clears_both() {
        let policy = CookiePolicy::for_deployment("http://localhost:1", "http://localhost:2");
        let session = MintedSession {
            access_token: "a".into(),
            access_expiry_ms: 0,
            refresh_token: "r".into(),
            refresh_expiry_ms: 0,
            handle: "h".into(),
        };
        let mut headers = HeaderMap::new();
        policy
            .append_session(&mut headers, &session)
            .expect("plain tokens are valid headers");
        let set: Vec<_> = headers.get_all(header::SET_COOKIE).iter().collect();
        assert_eq!(set.len(), 2);

        let mut cleared = HeaderMap::new();
        policy.append_cleared(&mut cleared);
        let cleared: Vec<&str> = cleared
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert_eq!(cleared.len(), 2);
        assert!(
            cleared.iter().all(|c| c.contains("Max-Age=0")),
            "{cleared:?}"
        );
    }

    #[test]
    fn a_past_expiry_is_zero_rather_than_negative() {
        assert_eq!(max_age_seconds(0), Some(0));
    }

    #[test]
    fn the_cookie_reader_takes_the_named_one_and_not_its_neighbour() {
        let headers = headers_with(&[(
            "cookie",
            "other=1; sRefreshToken=refresh-me; sAccessToken=access-me",
        )]);
        assert_eq!(
            read_cookie(&headers, REFRESH_COOKIE).as_deref(),
            Some("refresh-me")
        );
        assert_eq!(
            read_cookie(&headers, ACCESS_COOKIE).as_deref(),
            Some("access-me")
        );
        assert_eq!(read_cookie(&headers, "sNothing"), None);
    }

    #[test]
    fn the_exact_word_header_asks_for_header_mode() {
        for value in ["header", "Header", "  header  "] {
            assert!(
                wants_header_mode(&headers_with(&[(AUTH_MODE_HEADER, value)])),
                "{value:?}"
            );
        }
    }

    #[test]
    fn anything_but_header_stays_on_cookies() {
        assert!(!wants_header_mode(&HeaderMap::new()));
        for value in ["cookie", "", "headers", "header-mode", "true", "1"] {
            assert!(
                !wants_header_mode(&headers_with(&[(AUTH_MODE_HEADER, value)])),
                "{value:?} must not turn on header mode"
            );
        }
    }

    #[test]
    fn the_bearer_reader_takes_the_token_and_nothing_else() {
        assert_eq!(
            bearer_token(&headers_with(&[("authorization", "Bearer abc.def.ghi")])).as_deref(),
            Some("abc.def.ghi")
        );
        assert_eq!(bearer_token(&HeaderMap::new()), None);
        assert_eq!(
            bearer_token(&headers_with(&[("authorization", "abc.def.ghi")])),
            None
        );
        assert_eq!(
            bearer_token(&headers_with(&[("authorization", "Basic abc")])),
            None
        );
        assert_eq!(
            bearer_token(&headers_with(&[("authorization", "Bearer ")])),
            None
        );
    }

    #[test]
    fn header_mode_never_falls_back_to_the_refresh_cookie() {
        let native = headers_with(&[
            (AUTH_MODE_HEADER, "header"),
            ("cookie", "sRefreshToken=the-httponly-one"),
        ]);
        assert_eq!(refresh_token(&native), None);
    }

    #[test]
    fn cookie_mode_ignores_a_bearer_header_on_refresh() {
        let browser = headers_with(&[
            ("cookie", "sRefreshToken=the-httponly-one"),
            ("authorization", "Bearer an-access-token"),
        ]);
        assert_eq!(refresh_token(&browser).as_deref(), Some("the-httponly-one"));
    }
}
