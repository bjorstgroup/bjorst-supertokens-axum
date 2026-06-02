//! SuperTokens session verification extractor for Axum.
//!
//! Verifies access tokens by calling the SuperTokens Core REST API.
//! No Rust SDK exists for SuperTokens, so we call the Core's
//! `POST /recipe/session/verify` endpoint directly via `reqwest`.
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
            let user_id =
                Uuid::parse_str(&s.user_id).map_err(|_| "invalid user_id in session")?;
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

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let token =
            extract_token(parts).ok_or(Unauthorized("no session token provided"))?;
        verify_token(state.http_client(), state.supertokens_url(), &token)
            .await
            .map_err(Unauthorized)
    }
}
