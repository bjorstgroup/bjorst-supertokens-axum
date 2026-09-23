# bjorst-supertokens-axum

SuperTokens for Axum. SuperTokens publishes no Rust backend SDK, so this crate
is how a Rust API verifies sessions and, if it signs people in itself, talks to
the SuperTokens core directly.

## Usage

```toml
[dependencies]
bjorst-supertokens-axum = { git = "https://github.com/bjorstgroup/bjorst-supertokens-axum", tag = "v0.2.0" }
```

---

### Simple extractor

For apps that only need `user_id` and `session_handle`. Implement `HasSupertokens` on your `AppState` and add `AuthUser` as an extractor.

```rust
use bjorst_supertokens_axum::{AuthUser, HasSupertokens};

#[derive(Clone)]
struct AppState {
    http: reqwest::Client,
    st_url: String,
}

impl HasSupertokens for AppState {
    fn supertokens_url(&self) -> &str { &self.st_url }
    fn http_client(&self) -> &reqwest::Client { &self.http }
}

async fn protected(user: AuthUser) -> String {
    format!("hello {}", user.user_id)
}
```

Token is extracted from `Authorization: Bearer <token>` or the `sAccessToken` cookie.

---

### Low-level session API

For apps with custom JWT claims or session-init flows.

```rust
use bjorst_supertokens_axum::{
    SuperTokensConfig, VerifyCache, build_verify_cache,
    verify_claims, verify_raw,
};

// Build once at startup, store in AppState.
let cache: VerifyCache<MyClaims> = build_verify_cache();

// In a handler:
let claims = verify_claims::<MyClaims>(headers, &client, &config).await?;

// For session-init (before custom claims exist):
let raw = verify_raw(headers, &client, &config).await?;
// raw.existing_payload, raw.handle, raw.access_token, raw.supertokens_user_id
```

`VerifyCache` is keyed by SHA-256 of the token (TTL 30 s, capacity 10 000). Raw token strings are never stored in the cache.

Session verification uses `checkDatabase: false` — JWT signature only, no DB round-trip. Revoked sessions are detected when the token expires (~1 h default).

---

### Signing people in: `CoreClient` and `transport`

For an API that serves its own sign-up, sign-in, refresh, verification and
reset routes. `CoreClient` makes the calls to the core; the routes, and
anything the application decides about a person, stay in the application.

```rust
use bjorst_supertokens_axum::{CoreClient, SignIn, SuperTokensConfig, transport::CookiePolicy};

let core = CoreClient::new(&config, reqwest::Client::new());
let cookies = CookiePolicy::for_deployment("https://api.example.org", "https://example.org");

// In a sign-in handler:
if let SignIn::Ok(user) = core.sign_in(&email, &password).await? {
    let session = core.create_session(&user.id).await?;
    cookies.append_session(response.headers_mut(), &session)?;
}
```

`CoreClient` covers sign-up and sign-in, sessions (create, refresh, revoke,
list), email verification, password reset and change, names in the
user-metadata recipe, and moving accounts in from another provider
(`import_password_hash` for bcrypt or argon2 hashes, `map_user_id` to keep the
other provider's ids). Expected refusals (a wrong password, an address already
taken, a spent token) come back as values; `CoreError` is only for a core that
is unreachable or answers something unexpected, and it keeps the core's own
plain-text explanation.

`transport` sets and clears the `sAccessToken` and `sRefreshToken` cookies
(`HttpOnly`, `SameSite=Lax`, `Secure` over https, scoped to the parent domain
the API and website share), and implements header mode for native apps: a
request carrying `st-auth-mode: header` gets tokens in the body, and on
refresh its token is read from `Authorization`, never from the cookie.

Call `CoreClient::check_credentials` once at startup. A wrong API key is
otherwise indistinguishable from every session having expired.

## Testing against a real core

The core does not always behave the way its documentation says, so every call
is tested against a running one. The tests are ignored by default; the header
of `tests/core_live.rs` has the commands to start a Postgres-backed core and
run them:

```sh
SUPERTOKENS_CONNECTION_URI=http://localhost:3667 \
SUPERTOKENS_API_KEY=a-key-of-at-least-twenty-characters \
  cargo test --test core_live -- --ignored
```

Tested against `supertokens/supertokens-postgresql:12.1`.
