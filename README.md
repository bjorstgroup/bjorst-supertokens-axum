# bjorst-supertokens-axum

SuperTokens session verification for Axum. Supports two usage patterns.

## Usage

```toml
[dependencies]
bjorst-supertokens-axum = { git = "https://github.com/bjorstgroup/bjorst-supertokens-axum" }
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
