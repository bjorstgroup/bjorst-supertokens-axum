//! A client for the SuperTokens core's own HTTP interface (its "CDI").
//!
//! SuperTokens publishes no Rust backend SDK, so an axum API that signs people
//! in itself talks to the core directly: sign-up, sign-in, sessions, email
//! verification, password reset and user metadata. This module is that
//! conversation and nothing else. Tenancy, roles, which routes exist and what
//! they answer stay in the application.
//!
//! Extracted from Gakuin's `auth::provider::supertokens`, where every call was
//! probed against `supertokens/supertokens-postgresql:12.1` before it was
//! written. The core does not always behave the way its documentation says, and
//! the answers it actually gives are kept here as tests (`tests/core_live.rs`):
//!
//! * `GET /recipe/users/by-email` answers `{"status":"OK","users":[]}` for a
//!   user who exists. The lookup that answers is `GET /users/by-accountinfo`
//!   — with no `/recipe` prefix.
//! * Names live at `/recipe/user/metadata`. `/recipe/usermetadata` answers the
//!   four bytes `Not found`, with no JSON.
//! * A request the core dislikes answers a 4xx in **plain text**, not JSON.
//!   Omitting `useDynamicSigningKey` on refresh is `400 Field name
//!   'useDynamicSigningKey' is invalid in JSON input`. [`CoreError::Unreadable`]
//!   carries that text, because it is the only place the mistake is named.
//! * A wrong API key is `401 Invalid API key`, also in plain text. See
//!   [`CoreClient::check_credentials`].
//! * With a user id mapping in place (`POST /recipe/userid/map`), the core
//!   answers with the **external** id everywhere: sign-in, the session, and
//!   `/recipe/session/verify`. The application never translates.

use reqwest::{Client, RequestBuilder, StatusCode};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::json;
use thiserror::Error;

use crate::SuperTokensConfig;

/// How much of an unreadable body to keep in an error. Enough for the core's
/// plain-text sentences, which are short; not enough to log a page of HTML
/// from a proxy that answered in its place.
const BODY_EXCERPT: usize = 200;

// ── Errors ───────────────────────────────────────────────────────────────────

/// A call to the core that did not produce an answer the caller can act on.
///
/// Expected refusals are not errors. A wrong password, an address already
/// taken, a spent refresh token or a stale reset link each come back as an
/// ordinary value ([`SignIn`], [`SignUp`], `Option`, `bool`). What is left here
/// is the deployment's fault, never the person's.
#[derive(Debug, Error)]
pub enum CoreError {
    /// The request never got an answer.
    #[error("could not reach the SuperTokens core: {0}")]
    Unreachable(#[source] reqwest::Error),

    /// The core answered, but not with the JSON this call expects. The body is
    /// kept (shortened), because the core explains itself in plain text.
    #[error("the SuperTokens core answered {status} with something unreadable: {body}")]
    Unreadable {
        /// The HTTP status the core answered with.
        status: StatusCode,
        /// The start of what it said.
        body: String,
    },

    /// The core answered in JSON with a status this call has no meaning for.
    #[error("the SuperTokens core answered `{status}` to {operation}")]
    Refused {
        /// What was being asked, in words, e.g. `"a sign-in"`.
        operation: &'static str,
        /// The core's own status word.
        status: String,
    },

    /// The core said `OK` and left out something it always sends. This is what
    /// a CDI version change looks like. A session with no refresh token would
    /// work until the access token expired, an hour later, for everybody at once.
    #[error("the SuperTokens core {0}")]
    Incomplete(&'static str),
}

// ── Answers ──────────────────────────────────────────────────────────────────

/// A person as the core holds them.
#[derive(Debug, Clone, Deserialize)]
pub struct CoreUser {
    /// The user id sessions carry: the external id if one is mapped, otherwise
    /// the core's own UUID.
    pub id: String,
    /// One entry per way of signing in. For email and password, one entry.
    #[serde(rename = "loginMethods", default)]
    pub login_methods: Vec<LoginMethod>,
}

/// One way a person signs in, and whether its address is confirmed.
#[derive(Debug, Clone, Deserialize)]
pub struct LoginMethod {
    /// The address, or empty for a method that has none.
    #[serde(default)]
    pub email: String,
    /// Whether the address has been confirmed.
    #[serde(default)]
    pub verified: bool,
}

impl CoreUser {
    /// The first confirmed address.
    ///
    /// The core lists login methods in the order they were joined, which says
    /// nothing about which address is trustworthy. An unconfirmed address is
    /// one anybody could have typed.
    pub fn confirmed_email(&self) -> Option<&str> {
        self.addresses()
            .find(|m| m.verified)
            .map(|m| m.email.as_str())
    }

    /// The first address at all, confirmed or not. Use it to tell someone
    /// *which* address to confirm, never to decide who they are.
    pub fn first_email(&self) -> Option<&str> {
        self.addresses().next().map(|m| m.email.as_str())
    }

    fn addresses(&self) -> impl Iterator<Item = &LoginMethod> {
        self.login_methods
            .iter()
            .filter(|m| !m.email.trim().is_empty())
    }
}

/// The answer to a sign-up.
#[derive(Debug, Clone)]
pub enum SignUp {
    /// A new account.
    Created(CoreUser),
    /// The address already has an account.
    EmailTaken,
}

/// The answer to a sign-in.
///
/// A wrong password and an address nobody holds are the same answer, on
/// purpose: telling them apart would let anyone test which addresses have
/// accounts.
#[derive(Debug, Clone)]
pub enum SignIn {
    /// The password was right.
    Ok(CoreUser),
    /// It was not, or there is no such address.
    WrongCredentials,
}

/// A session the core has just minted or refreshed.
///
/// Expiries are **absolute milliseconds since the epoch**, as the core reports
/// them, not durations. Read as a duration, they produce a cookie that expired
/// in 1970.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedSession {
    /// The access token, verified on every request.
    pub access_token: String,
    /// When it expires.
    pub access_expiry_ms: i64,
    /// The refresh token, exchanged for a new pair.
    pub refresh_token: String,
    /// When it expires.
    pub refresh_expiry_ms: i64,
    /// The session handle, which revokes it.
    pub handle: String,
}

/// One of a person's live sessions, for a page that lists their devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    /// The session handle.
    pub handle: String,
    /// When it was created, in epoch milliseconds.
    pub created_ms: i64,
    /// When it expires, in epoch milliseconds.
    pub expiry_ms: i64,
}

/// The names held in the user-metadata recipe. Empty when none were written,
/// which is the ordinary case for anyone who signed themselves up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Names {
    /// First name, trimmed.
    pub first: String,
    /// Last name, trimmed.
    pub last: String,
}

/// What [`CoreClient::check_credentials`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialCheck {
    /// The core is there and accepts the key.
    Accepted,
    /// The core is there and rejects the key. Refuse to start: otherwise every
    /// sign-in answers 401 and nothing in the log names the key.
    KeyRejected,
    /// The core answered something else to a version check.
    Unexpected(StatusCode),
    /// The core could not be reached. It may still be starting.
    Unreachable(String),
}

/// A password hash algorithm the core can import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// `$2a$`, `$2b$` or `$2y$`.
    Bcrypt,
    /// `$argon2id$` and its siblings.
    Argon2,
}

impl HashAlgorithm {
    fn as_core_word(self) -> &'static str {
        match self {
            Self::Bcrypt => "BCRYPT",
            Self::Argon2 => "ARGON2",
        }
    }
}

// ── The client ───────────────────────────────────────────────────────────────

/// A connection to one SuperTokens core.
///
/// Cheap to clone: `reqwest::Client` is reference-counted. Build one at startup
/// and keep it in the application state.
#[derive(Debug, Clone)]
pub struct CoreClient {
    base: String,
    api_key: Option<String>,
    http: Client,
}

impl CoreClient {
    /// A client for the core named by `config`.
    ///
    /// A trailing slash on the URL is dropped. It is the ordinary operator
    /// typo, and every URL here is built by concatenation, so it would produce
    /// `…:3567//user/id`, which the core answers `Not found` to.
    pub fn new(config: &SuperTokensConfig, http: Client) -> Self {
        Self {
            base: config.connection_uri.trim_end_matches('/').to_owned(),
            api_key: config.api_key.clone(),
            http,
        }
    }

    /// The core's URL, without a trailing slash.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Ask the core whether it is there and whether it accepts our key.
    ///
    /// Call it once at startup. A wrong key is otherwise invisible: the core
    /// answers `401 Invalid API key` in plain text, verification reads any
    /// failure as "this token did not verify", and every person who signs in
    /// gets a 401 that looks exactly like an expired session.
    pub async fn check_credentials(&self) -> CredentialCheck {
        match self.get("/apiversion").send().await {
            Ok(res) if res.status() == StatusCode::UNAUTHORIZED => CredentialCheck::KeyRejected,
            Ok(res) if !res.status().is_success() => CredentialCheck::Unexpected(res.status()),
            Ok(_) => CredentialCheck::Accepted,
            Err(e) => CredentialCheck::Unreachable(e.to_string()),
        }
    }

    // ── Accounts ─────────────────────────────────────────────────────────────

    /// Create an email-and-password account.
    pub async fn sign_up(&self, email: &str, password: &str) -> Result<SignUp, CoreError> {
        let body: UserAnswer = self
            .read(
                self.post("/recipe/signup")
                    .json(&json!({ "email": email, "password": password })),
            )
            .await?;
        match body.status.as_str() {
            "OK" => body.user.map(SignUp::Created).ok_or(CoreError::Incomplete(
                "created an account and returned no user",
            )),
            "EMAIL_ALREADY_EXISTS_ERROR" => Ok(SignUp::EmailTaken),
            _ => Err(refused("a sign-up", body.status)),
        }
    }

    /// Check an address and a password.
    pub async fn sign_in(&self, email: &str, password: &str) -> Result<SignIn, CoreError> {
        let body: UserAnswer = self
            .read(
                self.post("/recipe/signin")
                    .json(&json!({ "email": email, "password": password })),
            )
            .await?;
        match body.status.as_str() {
            "OK" => body
                .user
                .map(SignIn::Ok)
                .ok_or(CoreError::Incomplete("accepted a sign-in and named nobody")),
            "WRONG_CREDENTIALS_ERROR" => Ok(SignIn::WrongCredentials),
            _ => Err(refused("a sign-in", body.status)),
        }
    }

    /// Create an account from a password hash another system made, so the
    /// person keeps their password. Verified on 12.1 with a `$2y$` bcrypt hash:
    /// the original password then signs in.
    ///
    /// Importing for an address that already exists replaces that account's
    /// password hash rather than refusing.
    pub async fn import_password_hash(
        &self,
        email: &str,
        hash: &str,
        algorithm: HashAlgorithm,
    ) -> Result<CoreUser, CoreError> {
        let body: UserAnswer = self
            .read(self.post("/recipe/user/passwordhash/import").json(&json!({
                "email": email,
                "passwordHash": hash,
                "hashingAlgorithm": algorithm.as_core_word(),
            })))
            .await?;
        match body.status.as_str() {
            "OK" => body.user.ok_or(CoreError::Incomplete(
                "imported an account and returned no user",
            )),
            _ => Err(refused("a password hash import", body.status)),
        }
    }

    /// Give a core user an external id, so that every session, sign-in and
    /// verification carries `external_id` instead of the core's UUID. For
    /// keeping another provider's ids when moving people over.
    pub async fn map_user_id(
        &self,
        supertokens_id: &str,
        external_id: &str,
    ) -> Result<(), CoreError> {
        let body: StatusOnly = self
            .read(self.post("/recipe/userid/map").json(&json!({
                "superTokensUserId": supertokens_id,
                "externalUserId": external_id,
            })))
            .await?;
        ok_or_refused("a user id mapping", body.status)
    }

    /// The user with this id, or `None` if there is none.
    pub async fn user_by_id(&self, user_id: &str) -> Result<Option<CoreUser>, CoreError> {
        let body: UserAnswer = self
            .read(self.get("/user/id").query(&[("userId", user_id)]))
            .await?;
        match body.status.as_str() {
            "OK" => body
                .user
                .map(Some)
                .ok_or(CoreError::Incomplete("found a user and returned none")),
            "UNKNOWN_USER_ID_ERROR" => Ok(None),
            _ => Err(refused("a user lookup", body.status)),
        }
    }

    /// The user holding this address, or `None`.
    ///
    /// Through `/users/by-accountinfo`, because `/recipe/users/by-email`
    /// answers an empty list for users who exist. `doUnionOfAccountInfo` makes
    /// it match an address held by any of a linked account's login methods, so
    /// it cannot answer "nobody" about an address someone can sign in with.
    pub async fn find_by_email(&self, email: &str) -> Result<Option<CoreUser>, CoreError> {
        let body: UsersAnswer = self
            .read(
                self.get("/users/by-accountinfo")
                    .query(&[("email", email), ("doUnionOfAccountInfo", "true")]),
            )
            .await?;
        Ok(body.users.into_iter().next())
    }

    // ── Sessions ─────────────────────────────────────────────────────────────

    /// Mint a session for a user.
    ///
    /// The access token carries no custom claims. Anything an application
    /// decides about a person belongs in its own database, read per request.
    /// In the token, a revoked role would outlive its revocation by the
    /// token's lifetime. Anti-CSRF is off: the session cookie is
    /// `SameSite=Lax` (see [`crate::transport`]), which is the fence anti-CSRF
    /// would otherwise be.
    pub async fn create_session(&self, user_id: &str) -> Result<MintedSession, CoreError> {
        let body: SessionAnswer = self
            .read(self.post("/recipe/session").json(&json!({
                "userId": user_id,
                "userDataInJWT": {},
                "userDataInDatabase": {},
                "enableAntiCsrf": false,
                "useDynamicSigningKey": false,
            })))
            .await?;
        body.into_minted()
    }

    /// Exchange a refresh token for a new pair, or `None` when the session has
    /// ended: spent, revoked, or signed by keys the core has since rotated.
    pub async fn refresh_session(
        &self,
        refresh_token: &str,
    ) -> Result<Option<MintedSession>, CoreError> {
        let body: SessionAnswer = self
            .read(self.post("/recipe/session/refresh").json(&json!({
                "refreshToken": refresh_token,
                "enableAntiCsrf": false,
                // Required here, unlike on create. Leaving it out is a 400 in
                // plain text.
                "useDynamicSigningKey": false,
            })))
            .await?;
        match body.status.as_str() {
            "OK" => body.into_minted().map(Some),
            _ => Ok(None),
        }
    }

    /// End one session. Ending a handle the core has never heard of succeeds:
    /// the caller asked for it to be gone, and it is.
    pub async fn revoke_session(&self, handle: &str) -> Result<(), CoreError> {
        let body: StatusOnly = self
            .read(
                self.post("/recipe/session/remove")
                    .json(&json!({ "sessionHandles": [handle] })),
            )
            .await?;
        ok_or_refused("a session removal", body.status)
    }

    /// A person's live sessions.
    ///
    /// One call per session, because the core has no bulk form. That suits a
    /// settings page; it does not suit a request path.
    pub async fn sessions_for(&self, user_id: &str) -> Result<Vec<SessionSummary>, CoreError> {
        let handles: HandlesAnswer = self
            .read(
                self.get("/recipe/session/user")
                    .query(&[("userId", user_id)]),
            )
            .await?;

        let mut sessions = Vec::with_capacity(handles.session_handles.len());
        for handle in handles.session_handles {
            let detail: SessionDetail = self
                .read(
                    self.get("/recipe/session")
                        .query(&[("sessionHandle", handle.as_str())]),
                )
                .await?;
            // A session can end between the two calls. It is simply not listed.
            if detail.status == "OK" {
                sessions.push(SessionSummary {
                    handle,
                    created_ms: detail.time_created.unwrap_or_default(),
                    expiry_ms: detail.expiry.unwrap_or_default(),
                });
            }
        }
        Ok(sessions)
    }

    // ── Email verification ───────────────────────────────────────────────────

    /// A token to email so the person can confirm their address, or `None`
    /// when it is already confirmed and there is nothing to send.
    pub async fn email_verification_token(
        &self,
        user_id: &str,
        email: &str,
    ) -> Result<Option<String>, CoreError> {
        let body: TokenAnswer = self
            .read(
                self.post("/recipe/user/email/verify/token")
                    .json(&json!({ "userId": user_id, "email": email })),
            )
            .await?;
        match body.status.as_str() {
            "OK" => body.token.map(Some).ok_or(CoreError::Incomplete(
                "minted a verification token and sent none",
            )),
            "EMAIL_ALREADY_VERIFIED_ERROR" => Ok(None),
            _ => Err(refused("a verification token", body.status)),
        }
    }

    /// Spend a verification token. `false` for one that is spent, expired or
    /// not the core's.
    pub async fn verify_email(&self, token: &str) -> Result<bool, CoreError> {
        let body: StatusOnly = self
            .read(
                self.post("/recipe/user/email/verify")
                    .json(&json!({ "method": "token", "token": token })),
            )
            .await?;
        Ok(body.status == "OK")
    }

    // ── Passwords ────────────────────────────────────────────────────────────

    /// A token to email so the person can choose a new password.
    pub async fn password_reset_token(
        &self,
        user_id: &str,
        email: &str,
    ) -> Result<String, CoreError> {
        let body: TokenAnswer = self
            .read(
                self.post("/recipe/user/password/reset/token")
                    .json(&json!({ "userId": user_id, "email": email })),
            )
            .await?;
        match body.status.as_str() {
            "OK" => body
                .token
                .ok_or(CoreError::Incomplete("minted a reset token and sent none")),
            _ => Err(refused("a password reset token", body.status)),
        }
    }

    /// Spend a reset token on a new password. `false` for a token that is
    /// spent, expired or not the core's.
    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<bool, CoreError> {
        let body: StatusOnly = self
            .read(self.post("/recipe/user/password/reset").json(&json!({
                "method": "token",
                "token": token,
                "newPassword": new_password,
            })))
            .await?;
        match body.status.as_str() {
            "OK" => Ok(true),
            "RESET_PASSWORD_INVALID_TOKEN_ERROR" => Ok(false),
            _ => Err(refused("a password reset", body.status)),
        }
    }

    /// Set a new password for someone who is signed in.
    ///
    /// The core has no change-password call; minting a reset token and
    /// spending it at once is what its own SDKs do. **Proving the old password
    /// is the caller's job** ([`Self::sign_in`]). Doing it anywhere else would
    /// make this a way to set a password without knowing one.
    pub async fn set_password(
        &self,
        user_id: &str,
        email: &str,
        new_password: &str,
    ) -> Result<bool, CoreError> {
        let token = self.password_reset_token(user_id, email).await?;
        self.reset_password(&token, new_password).await
    }

    // ── Names ────────────────────────────────────────────────────────────────

    /// The names in the user-metadata recipe, empty where none are held.
    pub async fn names(&self, user_id: &str) -> Result<Names, CoreError> {
        let body: MetadataAnswer = self
            .read(
                self.get("/recipe/user/metadata")
                    .query(&[("userId", user_id)]),
            )
            .await?;
        let trimmed = |v: Option<String>| v.unwrap_or_default().trim().to_owned();
        Ok(Names {
            first: trimmed(body.metadata.first_name),
            last: trimmed(body.metadata.last_name),
        })
    }

    /// Write the names to the user-metadata recipe.
    pub async fn set_names(&self, user_id: &str, first: &str, last: &str) -> Result<(), CoreError> {
        let body: StatusOnly = self
            .read(self.put("/recipe/user/metadata").json(&json!({
                "userId": user_id,
                "metadataUpdate": { "first_name": first, "last_name": last },
            })))
            .await?;
        ok_or_refused("a metadata update", body.status)
    }

    // ── Plumbing ─────────────────────────────────────────────────────────────

    fn get(&self, path: &str) -> RequestBuilder {
        self.with_key(self.http.get(format!("{}{path}", self.base)))
    }

    fn post(&self, path: &str) -> RequestBuilder {
        self.with_key(self.http.post(format!("{}{path}", self.base)))
    }

    fn put(&self, path: &str) -> RequestBuilder {
        self.with_key(self.http.put(format!("{}{path}", self.base)))
    }

    fn with_key(&self, request: RequestBuilder) -> RequestBuilder {
        match &self.api_key {
            Some(key) => request.header("api-key", key),
            None => request,
        }
    }

    /// Send, and read the answer as `T`, keeping the text when it is not JSON.
    async fn read<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T, CoreError> {
        let res = request.send().await.map_err(CoreError::Unreachable)?;
        let status = res.status();
        let text = res.text().await.map_err(CoreError::Unreachable)?;
        parse(status, &text)
    }
}

fn parse<T: DeserializeOwned>(status: StatusCode, text: &str) -> Result<T, CoreError> {
    serde_json::from_str(text).map_err(|_| CoreError::Unreadable {
        status,
        body: text.chars().take(BODY_EXCERPT).collect(),
    })
}

fn refused(operation: &'static str, status: String) -> CoreError {
    CoreError::Refused { operation, status }
}

fn ok_or_refused(operation: &'static str, status: String) -> Result<(), CoreError> {
    if status == "OK" {
        Ok(())
    } else {
        Err(refused(operation, status))
    }
}

// ── The core's wire shapes ───────────────────────────────────────────────────

#[derive(Deserialize)]
struct StatusOnly {
    status: String,
}

#[derive(Deserialize)]
struct UserAnswer {
    status: String,
    #[serde(default)]
    user: Option<CoreUser>,
}

#[derive(Deserialize)]
struct UsersAnswer {
    #[serde(default)]
    users: Vec<CoreUser>,
}

#[derive(Deserialize)]
struct TokenAnswer {
    status: String,
    #[serde(default)]
    token: Option<String>,
}

#[derive(Deserialize)]
struct HandlesAnswer {
    #[serde(rename = "sessionHandles", default)]
    session_handles: Vec<String>,
}

#[derive(Deserialize)]
struct SessionDetail {
    status: String,
    #[serde(rename = "timeCreated", default)]
    time_created: Option<i64>,
    #[serde(default)]
    expiry: Option<i64>,
}

#[derive(Deserialize)]
struct SessionAnswer {
    #[serde(default = "ok_status")]
    status: String,
    #[serde(rename = "accessToken", default)]
    access_token: Option<CoreToken>,
    #[serde(rename = "refreshToken", default)]
    refresh_token: Option<CoreToken>,
    #[serde(default)]
    session: Option<CoreSessionInfo>,
}

#[derive(Deserialize)]
struct CoreToken {
    token: String,
    expiry: i64,
}

#[derive(Deserialize)]
struct CoreSessionInfo {
    handle: String,
}

#[derive(Deserialize)]
struct MetadataAnswer {
    #[serde(default)]
    metadata: CoreMetadata,
}

#[derive(Deserialize, Default)]
struct CoreMetadata {
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
}

fn ok_status() -> String {
    "OK".to_owned()
}

impl SessionAnswer {
    fn into_minted(self) -> Result<MintedSession, CoreError> {
        let access = self.access_token.ok_or(CoreError::Incomplete(
            "minted a session with no access token",
        ))?;
        let refresh = self.refresh_token.ok_or(CoreError::Incomplete(
            "minted a session with no refresh token",
        ))?;
        let session = self
            .session
            .ok_or(CoreError::Incomplete("minted a session with no handle"))?;
        Ok(MintedSession {
            access_token: access.token,
            access_expiry_ms: access.expiry,
            refresh_token: refresh.token,
            refresh_expiry_ms: refresh.expiry,
            handle: session.handle,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(uri: &str) -> CoreClient {
        CoreClient::new(
            &SuperTokensConfig {
                connection_uri: uri.to_owned(),
                api_key: None,
            },
            Client::new(),
        )
    }

    fn user(methods: &[(&str, bool)]) -> CoreUser {
        CoreUser {
            id: "st-1".into(),
            login_methods: methods
                .iter()
                .map(|(email, verified)| LoginMethod {
                    email: (*email).into(),
                    verified: *verified,
                })
                .collect(),
        }
    }

    #[test]
    fn a_trailing_slash_does_not_reach_the_url() {
        assert_eq!(client("http://core:3567/").base(), "http://core:3567");
        assert_eq!(client("http://core:3567").base(), "http://core:3567");
    }

    #[test]
    fn the_confirmed_address_is_chosen_even_when_it_is_not_first() {
        let person = user(&[("typo@example.com", false), ("ada@example.com", true)]);
        assert_eq!(person.confirmed_email(), Some("ada@example.com"));
    }

    #[test]
    fn an_unconfirmed_address_is_not_confirmed_but_can_be_named() {
        let person = user(&[("ada@example.com", false)]);
        assert_eq!(person.confirmed_email(), None);
        assert_eq!(person.first_email(), Some("ada@example.com"));
    }

    #[test]
    fn a_blank_address_is_no_address() {
        let person = user(&[("  ", true)]);
        assert_eq!(person.confirmed_email(), None);
        assert_eq!(person.first_email(), None);
    }

    #[test]
    fn an_empty_user_list_parses_rather_than_erroring() {
        let answer: UsersAnswer =
            parse(StatusCode::OK, r#"{"status":"OK","users":[]}"#).expect("the core's own shape");
        assert!(answer.users.is_empty());
    }

    #[test]
    fn absent_metadata_parses_as_no_names() {
        let answer: MetadataAnswer = parse(StatusCode::OK, r#"{"metadata":{},"status":"OK"}"#)
            .expect("the core's own shape");
        assert_eq!(answer.metadata.first_name, None);
    }

    #[test]
    fn a_plain_text_answer_keeps_what_the_core_said() {
        let err = parse::<StatusOnly>(
            StatusCode::BAD_REQUEST,
            "Field name 'useDynamicSigningKey' is invalid in JSON input",
        )
        .err()
        .expect("plain text is not JSON");
        let CoreError::Unreadable { status, body } = err else {
            panic!("plain text is an unreadable answer, not a refusal");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("useDynamicSigningKey"), "{body}");
    }

    #[test]
    fn a_long_unreadable_answer_is_cut_short() {
        let page = "x".repeat(10_000);
        let Err(CoreError::Unreadable { body, .. }) =
            parse::<StatusOnly>(StatusCode::BAD_GATEWAY, &page)
        else {
            panic!("a page of HTML is unreadable");
        };
        assert_eq!(body.len(), BODY_EXCERPT);
    }

    #[test]
    fn a_session_with_no_refresh_token_is_refused_rather_than_half_used() {
        let answer: SessionAnswer = parse(
            StatusCode::OK,
            r#"{"status":"OK","accessToken":{"token":"a","expiry":1},"session":{"handle":"h"}}"#,
        )
        .expect("the shape parses");
        let err = answer.into_minted().expect_err("no refresh token");
        assert!(err.to_string().contains("refresh token"), "{err}");
    }

    #[test]
    fn a_whole_session_is_minted_with_its_absolute_expiries() {
        let answer: SessionAnswer = parse(
            StatusCode::OK,
            r#"{"status":"OK",
                "accessToken":{"token":"a","expiry":1760000060000},
                "refreshToken":{"token":"r","expiry":1768000000000},
                "session":{"handle":"h","userId":"u"}}"#,
        )
        .expect("the shape parses");
        let minted = answer.into_minted().expect("everything is there");
        assert_eq!(minted.access_expiry_ms, 1_760_000_060_000);
        assert_eq!(minted.refresh_expiry_ms, 1_768_000_000_000);
        assert_eq!(minted.handle, "h");
    }

    #[test]
    fn an_unknown_user_parses_as_a_status_with_no_user() {
        let answer: UserAnswer =
            parse(StatusCode::OK, r#"{"status":"UNKNOWN_USER_ID_ERROR"}"#).expect("parses");
        assert!(answer.user.is_none());
    }
}
