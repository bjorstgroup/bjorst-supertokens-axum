//! SuperTokens session verification for Axum.
//!
//! ## Two APIs — choose one per project
//!
//! ### Simple extractor (existing, e.g. kyokai)
//! Implement [`HasSupertokens`] on your `AppState` and add `AuthUser` as an
//! extractor parameter. The library verifies the token and returns a basic
//! `{ user_id, session_handle }` struct.
//!
//! ### Low-level session API (new, e.g. gakuin)
//! Use [`verify_raw`] / [`verify_claims`] directly for full control over
//! claim parsing, in-process caching ([`VerifyCache`]), and session init flows
//! that need the raw `existing_payload` before custom claims exist.
//!
//! ## Usage
//!
//! 1. Implement [`HasSupertokens`] on your Axum `AppState`.
//! 2. Add `AuthUser` as an extractor parameter on any protected handler.
//!
//! ```ignore
//! use bjorst_supertokens_axum::{AuthUser, HasSupertokens};
//!
//! #[derive(Clone)]
//! struct AppState {
//!     http_client: reqwest::Client,
//!     supertokens_url: String,
//! }
//!
//! impl HasSupertokens for AppState {
//!     fn supertokens_url(&self) -> &str { &self.supertokens_url }
//!     fn http_client(&self) -> &reqwest::Client { &self.http_client }
//! }
//!
//! async fn protected(user: AuthUser) -> String {
//!     format!("hello {}", user.user_id)
//! }
//! ```

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Implemented by an Axum `AppState` that holds SuperTokens configuration.
pub trait HasSupertokens {
    /// Base URL of the SuperTokens Core service, e.g. `http://localhost:3567`.
    fn supertokens_url(&self) -> &str;

    /// Shared `reqwest::Client` for outbound HTTP calls to the Core.
    fn http_client(&self) -> &reqwest::Client;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Verified caller identity extracted from a SuperTokens session token.
#[derive(Debug, Clone)]
pub struct AuthUser {
    /// Internal SuperTokens user ID, parsed to UUID.
    pub user_id: Uuid,
    /// SuperTokens session handle (opaque; used for revocation).
    pub session_handle: String,
}

/// Axum rejection returned when session verification fails.
pub struct Unauthorized(pub &'static str);

impl IntoResponse for Unauthorized {
    fn into_response(self) -> Response {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized", "message": self.0 })),
        )
            .into_response()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal deserialization types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CoreVerifyResponse {
    status: String,
    session: Option<CoreSession>,
}

#[derive(Deserialize)]
struct CoreSession {
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "sessionHandle")]
    session_handle: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Token extraction
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the raw access token from the request.
///
/// Checks `Authorization: Bearer <token>` first, then the `sAccessToken`
/// cookie (the default cookie name used by SuperTokens clients).
fn extract_token(parts: &Parts) -> Option<String> {
    if let Some(v) = parts.headers.get(header::AUTHORIZATION) {
        if let Ok(s) = v.to_str() {
            if let Some(tok) = s.strip_prefix("Bearer ") {
                return Some(tok.to_owned());
            }
        }
    }

    if let Some(cookie_hdr) = parts.headers.get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_hdr.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("sAccessToken=") {
                    return Some(val.to_owned());
                }
            }
        }
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Core API call
// ─────────────────────────────────────────────────────────────────────────────

/// Verify a SuperTokens access token against the Core service.
///
/// `checkDatabase: false` verifies the JWT signature without a DB round-trip.
/// Revoked sessions won't be detected until the token expires (~1 h default).
pub async fn verify_token(
    http: &reqwest::Client,
    supertokens_url: &str,
    token: &str,
) -> Result<AuthUser, &'static str> {
    let url = format!("{supertokens_url}/recipe/session/verify");

    let resp = http
        .post(&url)
        .header("rid", "session")
        .json(&json!({
            "accessToken": token,
            "doAntiCsrfCheck": false,
            "enableAntiCsrf": false,
            "checkDatabase": false
        }))
        .send()
        .await
        .map_err(|_| "failed to reach auth service")?;

    let body: CoreVerifyResponse = resp
        .json()
        .await
        .map_err(|_| "invalid response from auth service")?;

    match body.status.as_str() {
        "OK" => {
            let s = body.session.ok_or("missing session in response")?;
            let user_id = Uuid::parse_str(&s.user_id).map_err(|_| "invalid user_id in session")?;
            Ok(AuthUser {
                user_id,
                session_handle: s.session_handle,
            })
        }
        "UNAUTHORISED" => Err("session unauthorised"),
        "TRY_REFRESH_TOKEN" => Err("access token expired — refresh and retry"),
        _ => Err("unexpected auth status from core"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Axum extractor
// ─────────────────────────────────────────────────────────────────────────────

impl<S> FromRequestParts<S> for AuthUser
where
    S: HasSupertokens + Send + Sync,
{
    type Rejection = Unauthorized;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = extract_token(parts).ok_or(Unauthorized("no session token provided"))?;
        verify_token(state.http_client(), state.supertokens_url(), &token)
            .await
            .map_err(Unauthorized)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Low-level session API
// ═════════════════════════════════════════════════════════════════════════════

use axum::http::HeaderMap;
use moka::future::Cache;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use thiserror::Error;

// ── Config ────────────────────────────────────────────────────────────────────

/// Minimal SuperTokens Core connection config.
#[derive(Debug, Clone)]
pub struct SuperTokensConfig {
    /// Base URL of the SuperTokens Core service, e.g. `http://localhost:3567`.
    pub connection_uri: String,
    /// Optional API key required by the Core service.
    pub api_key: Option<String>,
}

// ── Cache ─────────────────────────────────────────────────────────────────────

/// In-process verify cache keyed by SHA-256 of the access token.
///
/// `C` is the application's session claims type (or `AuthenticatedContext` for
/// apps that enrich claims before storing them). The TTL should be ≤ 30 s so
/// revoked sessions aren't cached for too long.
///
/// SECURITY: the cache is keyed by the *hash* of the token, never the raw
/// token string.
pub type VerifyCache<C> = Cache<[u8; 32], C>;

/// Build a default `VerifyCache` (10 000 entries, 30 s TTL).
pub fn build_verify_cache<C>() -> VerifyCache<C>
where
    C: Clone + Send + Sync + 'static,
{
    Cache::builder()
        .max_capacity(10_000)
        .time_to_live(std::time::Duration::from_secs(30))
        .build()
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum VerifySessionError {
    #[error("supertokens request failed: {0}")]
    Http(#[from] reqwest::Error),
}

// ── Raw session info ──────────────────────────────────────────────────────────

/// Raw session data returned by the SuperTokens Core `session/verify` endpoint.
///
/// Used by session-init flows where custom claims have not yet been written into
/// the access token. After enrichment, [`verify_claims`] should be used instead.
#[derive(Debug, Clone)]
pub struct RawSessionInfo {
    /// SuperTokens internal user ID (not the application's UUID).
    pub supertokens_user_id: String,
    /// Session handle — needed for `PUT /recipe/session` (claim updates).
    pub handle: String,
    /// The raw access token string (needed for `/recipe/session/regenerate`).
    pub access_token: String,
    /// Current access token payload; may be empty before session init.
    pub existing_payload: serde_json::Value,
}

// ── Token helpers ─────────────────────────────────────────────────────────────

/// Compute SHA-256 of an access token for use as a cache key.
///
/// SECURITY: never store the raw token — only this hash.
pub fn token_hash(access_token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(access_token.as_bytes());
    hasher.finalize().into()
}

/// Extract the access token from request headers.
///
/// Checks `Authorization: Bearer <token>` first, then the `sAccessToken`
/// cookie (used by `supertokens-web-js` in header-token mode).
pub fn extract_access_token(headers: &HeaderMap) -> Option<String> {
    extract_cookie_from_headers(headers, "sAccessToken").or_else(|| {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(ToOwned::to_owned)
    })
}

fn extract_cookie_from_headers(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie_header| {
            cookie_header.split(';').find_map(|cookie| {
                let trimmed = cookie.trim();
                let prefix = format!("{name}=");
                trimmed.strip_prefix(&prefix).map(ToOwned::to_owned)
            })
        })
}

// ── Internal deserialization ──────────────────────────────────────────────────

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyEnvelope {
    status: String,
    session: Option<VerifiedSession>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedSession {
    handle: String,
    user_id: String,
    #[serde(rename = "userDataInJWT", default)]
    user_data_in_jwt: serde_json::Value,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRequest {
    access_token: String,
    do_anti_csrf_check: bool,
    enable_anti_csrf: bool,
    check_database: bool,
}

// ── Core API call ─────────────────────────────────────────────────────────────

async fn call_verify(
    headers: &HeaderMap,
    client: &reqwest::Client,
    config: &SuperTokensConfig,
) -> Result<Option<(String, VerifiedSession)>, VerifySessionError> {
    let Some(access_token) = extract_access_token(headers) else {
        return Ok(None);
    };

    let start = std::time::Instant::now();

    let payload = VerifyRequest {
        access_token: access_token.clone(),
        do_anti_csrf_check: false,
        enable_anti_csrf: false,
        check_database: false,
    };

    let mut req = client
        .post(format!(
            "{}/recipe/session/verify",
            config.connection_uri.trim_end_matches('/')
        ))
        .json(&payload);

    if let Some(key) = &config.api_key {
        req = req.header("api-key", key);
    }

    let response = req.send().await?;
    let elapsed = start.elapsed().as_secs_f64();

    if !response.status().is_success() {
        metrics::counter!("st_verify_total", "result" => "err").increment(1);
        metrics::histogram!("st_verify_duration_seconds", "result" => "err").record(elapsed);
        return Ok(None);
    }

    let envelope: VerifyEnvelope = response.json().await?;
    if envelope.status != "OK" {
        metrics::counter!("st_verify_total", "result" => "err").increment(1);
        metrics::histogram!("st_verify_duration_seconds", "result" => "err").record(elapsed);
        return Ok(None);
    }

    let Some(session) = envelope.session else {
        metrics::counter!("st_verify_total", "result" => "err").increment(1);
        metrics::histogram!("st_verify_duration_seconds", "result" => "err").record(elapsed);
        return Ok(None);
    };

    metrics::counter!("st_verify_total", "result" => "miss").increment(1);
    metrics::histogram!("st_verify_duration_seconds", "result" => "miss").record(elapsed);

    Ok(Some((access_token, session)))
}

// ── Public verification functions ─────────────────────────────────────────────

/// Verify a session and return the raw session info including `existing_payload`.
///
/// Use this for session-init flows where custom claims haven't been written yet.
/// For normal request verification use [`verify_claims`].
pub async fn verify_raw(
    headers: &HeaderMap,
    client: &reqwest::Client,
    config: &SuperTokensConfig,
) -> Result<Option<RawSessionInfo>, VerifySessionError> {
    let Some((access_token, session)) = call_verify(headers, client, config).await? else {
        return Ok(None);
    };

    Ok(Some(RawSessionInfo {
        supertokens_user_id: session.user_id,
        handle: session.handle,
        access_token,
        existing_payload: session.user_data_in_jwt,
    }))
}

/// Verify a session and deserialise `userDataInJWT` into `C`.
///
/// Returns `None` when no token is present, when verification fails, or when
/// the JWT payload cannot be deserialised into `C`.
pub async fn verify_claims<C>(
    headers: &HeaderMap,
    client: &reqwest::Client,
    config: &SuperTokensConfig,
) -> Result<Option<C>, VerifySessionError>
where
    C: DeserializeOwned,
{
    let Some((_access_token, session)) = call_verify(headers, client, config).await? else {
        return Ok(None);
    };

    let Ok(claims) = serde_json::from_value::<C>(session.user_data_in_jwt) else {
        return Ok(None);
    };

    Ok(Some(claims))
}
