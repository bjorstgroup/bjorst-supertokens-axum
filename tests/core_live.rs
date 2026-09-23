//! `CoreClient` against a SuperTokens core that is actually running.
//!
//! The unit tests check shapes this library wrote down. These check the shapes
//! **the core sends**, which is the claim that matters: a client nobody ran
//! against the server has never been shown to work. Two of the calls here
//! (`/users/by-accountinfo`, `/recipe/user/metadata`) are not where the
//! documentation puts them, and both mistakes fail silently.
//!
//! `#[ignore]` by default, because CI has no core. Start one on Postgres, as
//! production runs it, and point the tests at it:
//!
//!     docker network create st
//!     docker run --rm -d --name st-pg --network st \
//!       -e POSTGRES_PASSWORD=st -e POSTGRES_DB=st postgres:16-alpine
//!     docker run --rm -d --name st-core --network st -p 127.0.0.1:3667:3567 \
//!       -e API_KEYS=a-key-of-at-least-twenty-characters \
//!       -e POSTGRESQL_CONNECTION_URI=postgresql://postgres:st@st-pg:5432/st \
//!       -e POSTGRESQL_TABLE_SCHEMA=auth \
//!       supertokens/supertokens-postgresql:12.1
//!
//!     SUPERTOKENS_CONNECTION_URI=http://localhost:3667 \
//!     SUPERTOKENS_API_KEY=a-key-of-at-least-twenty-characters \
//!       cargo test --test core_live -- --ignored
//!
//! **Not the in-memory core.** Given no database, the image keeps everything in
//! SQLite, which answers concurrent writes with a 500
//! (`SQLITE_LOCKED_SHAREDCACHE`), so these tests fail at random in parallel.
//! That says nothing about this client, or about production.
//!
//! The key must be twenty characters or more, or the core refuses to start and
//! says so only in its own log.

use axum::http::{header, HeaderMap};
use bjorst_supertokens_axum::{
    verify_raw, CoreClient, CredentialCheck, HashAlgorithm, SignIn, SignUp, SuperTokensConfig,
};
use uuid::Uuid;

const PASSWORD: &str = "Pw!probe2026probe";

/// `Imported!pass2026`, hashed with bcrypt (`htpasswd -nbBC 10`).
const BCRYPT_OF_IMPORTED: &str = "$2y$10$WehMJLaKIS0W6h3KEL5RJeqbhbSb2u9Q9IP1gZhz.osS8COdTN6EO";
const IMPORTED_PASSWORD: &str = "Imported!pass2026";

fn config() -> SuperTokensConfig {
    SuperTokensConfig {
        connection_uri: std::env::var("SUPERTOKENS_CONNECTION_URI").expect(
            "SUPERTOKENS_CONNECTION_URI is unset, so this test verified nothing. \
             The module header has the two commands that start a core.",
        ),
        api_key: std::env::var("SUPERTOKENS_API_KEY").ok(),
    }
}

fn core() -> CoreClient {
    CoreClient::new(&config(), reqwest::Client::new())
}

fn an_address() -> String {
    format!("probe-{}@example.com", Uuid::new_v4().simple())
}

async fn signed_up(core: &CoreClient, email: &str) -> String {
    match core
        .sign_up(email, PASSWORD)
        .await
        .expect("the sign-up call")
    {
        SignUp::Created(user) => user.id,
        SignUp::EmailTaken => panic!("a fresh address was already taken"),
    }
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {token}")
            .parse()
            .expect("a token is a header value"),
    );
    headers
}

// ── Credentials ──────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn the_configured_key_is_accepted_and_a_wrong_one_is_named() {
    assert_eq!(core().check_credentials().await, CredentialCheck::Accepted);

    let wrong = CoreClient::new(
        &SuperTokensConfig {
            api_key: Some("this-is-not-the-key-and-is-long-enough".into()),
            ..config()
        },
        reqwest::Client::new(),
    );
    assert_eq!(
        wrong.check_credentials().await,
        CredentialCheck::KeyRejected
    );
}

// ── Accounts ─────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn a_second_sign_up_for_the_same_address_is_taken_and_finds_the_first() {
    let core = core();
    let email = an_address();
    let id = signed_up(&core, &email).await;

    assert!(matches!(
        core.sign_up(&email, PASSWORD)
            .await
            .expect("the second call"),
        SignUp::EmailTaken
    ));
    let found = core
        .find_by_email(&email)
        .await
        .expect("the lookup")
        .expect("the address has an account");
    assert_eq!(found.id, id);
}

/// The quirk `find_by_email` exists to avoid, kept as a canary. If this starts
/// failing, the core has fixed `by-email`, which is good news, not a bug here.
#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn the_by_email_lookup_still_answers_empty_for_a_user_who_exists() {
    let core = core();
    let email = an_address();
    signed_up(&core, &email).await;

    let config = config();
    let mut request = reqwest::Client::new()
        .get(format!("{}/recipe/users/by-email", core.base()))
        .query(&[("email", email.as_str())]);
    if let Some(key) = &config.api_key {
        request = request.header("api-key", key);
    }
    let body: serde_json::Value = request
        .send()
        .await
        .expect("the call")
        .json()
        .await
        .expect("json");
    assert_eq!(body["users"], serde_json::json!([]));
}

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn an_unused_address_finds_nobody_and_an_unknown_id_is_none() {
    let core = core();
    assert!(core
        .find_by_email(&an_address())
        .await
        .expect("the lookup")
        .is_none());
    assert!(core
        .user_by_id("no-such-user")
        .await
        .expect("the lookup")
        .is_none());
}

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn a_wrong_password_and_an_unknown_address_answer_the_same() {
    let core = core();
    let email = an_address();
    let id = signed_up(&core, &email).await;

    let SignIn::Ok(user) = core.sign_in(&email, PASSWORD).await.expect("the sign-in") else {
        panic!("the right password was refused");
    };
    assert_eq!(user.id, id);

    for (label, address, password) in [
        ("wrong password", email.as_str(), "Nope!nope1nope1nope1"),
        ("unknown address", "nobody-here@example.com", PASSWORD),
    ] {
        let outcome = core
            .sign_in(address, password)
            .await
            .unwrap_or_else(|e| panic!("{label} should be a refusal, not a fault: {e}"));
        assert!(
            matches!(outcome, SignIn::WrongCredentials),
            "{label} was not refused"
        );
    }
}

// ── Sessions ─────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn a_session_verifies_as_its_user_and_carries_absolute_expiries() {
    let core = core();
    let id = signed_up(&core, &an_address()).await;
    let session = core.create_session(&id).await.expect("a session");

    assert!(
        session.access_expiry_ms > 1_700_000_000_000,
        "expiry {} is not an absolute epoch millisecond",
        session.access_expiry_ms
    );
    assert!(session.refresh_expiry_ms > session.access_expiry_ms);

    let verified = verify_raw(
        &bearer(&session.access_token),
        &reqwest::Client::new(),
        &config(),
    )
    .await
    .expect("the verify call")
    .expect("a fresh session verifies");
    assert_eq!(verified.supertokens_user_id, id);
    assert_eq!(verified.handle, session.handle);
}

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn a_refresh_token_buys_a_new_pair_once() {
    let core = core();
    let id = signed_up(&core, &an_address()).await;
    let first = core.create_session(&id).await.expect("a session");

    let second = core
        .refresh_session(&first.refresh_token)
        .await
        .expect("the refresh call")
        .expect("an unspent refresh token is honoured");
    assert_ne!(second.access_token, first.access_token);
    assert_eq!(second.handle, first.handle, "a refresh keeps the session");
}

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn revoking_one_session_leaves_the_others_and_lists_what_is_left() {
    let core = core();
    let id = signed_up(&core, &an_address()).await;
    let laptop = core.create_session(&id).await.expect("one");
    let phone = core.create_session(&id).await.expect("two");

    let before = core.sessions_for(&id).await.expect("the list");
    assert_eq!(before.len(), 2);

    core.revoke_session(&laptop.handle)
        .await
        .expect("the revoke");
    assert!(
        core.refresh_session(&laptop.refresh_token)
            .await
            .expect("the refresh call")
            .is_none(),
        "the revoked session still refreshes"
    );
    assert!(
        core.refresh_session(&phone.refresh_token)
            .await
            .expect("the refresh call")
            .is_some(),
        "signing out of one device signed the person out of the other"
    );

    let after = core.sessions_for(&id).await.expect("the list");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].handle, phone.handle);
}

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn revoking_a_handle_that_never_existed_is_a_success() {
    core()
        .revoke_session("no-such-handle")
        .await
        .expect("revoking nothing is not a failure");
}

// ── Email verification ───────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn confirming_an_address_is_what_makes_it_confirmed() {
    let core = core();
    let email = an_address();
    let id = signed_up(&core, &email).await;

    let before = core
        .user_by_id(&id)
        .await
        .expect("the lookup")
        .expect("exists");
    assert_eq!(before.confirmed_email(), None);
    assert_eq!(before.first_email(), Some(email.as_str()));

    assert!(!core
        .verify_email("not-a-token")
        .await
        .expect("the verify call"));

    let token = core
        .email_verification_token(&id, &email)
        .await
        .expect("the token call")
        .expect("an unconfirmed address has a token to send");
    assert!(core.verify_email(&token).await.expect("the verify call"));

    let after = core
        .user_by_id(&id)
        .await
        .expect("the lookup")
        .expect("exists");
    assert_eq!(after.confirmed_email(), Some(email.as_str()));

    assert!(
        core.email_verification_token(&id, &email)
            .await
            .expect("the token call")
            .is_none(),
        "a confirmed address was offered another confirmation"
    );
}

// ── Passwords ────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn a_reset_token_sets_a_password_once() {
    let core = core();
    let email = an_address();
    let id = signed_up(&core, &email).await;

    let token = core
        .password_reset_token(&id, &email)
        .await
        .expect("a token");
    assert!(core
        .reset_password(&token, "New!pass2026pass")
        .await
        .expect("the reset"));
    assert!(
        !core
            .reset_password(&token, "Again!pass2026")
            .await
            .expect("the reset call"),
        "a spent token was honoured"
    );
    assert!(matches!(
        core.sign_in(&email, "New!pass2026pass")
            .await
            .expect("the sign-in"),
        SignIn::Ok(_)
    ));
}

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn set_password_replaces_the_old_one() {
    let core = core();
    let email = an_address();
    let id = signed_up(&core, &email).await;

    assert!(core
        .set_password(&id, &email, "Changed!pass2026")
        .await
        .expect("the change"));
    assert!(matches!(
        core.sign_in(&email, PASSWORD).await.expect("the sign-in"),
        SignIn::WrongCredentials
    ));
}

// ── Names ────────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn names_read_back_as_written_and_as_empty_before() {
    let core = core();
    let id = signed_up(&core, &an_address()).await;

    let before = core.names(&id).await.expect("the read");
    assert_eq!(before.first, "");

    core.set_names(&id, "Ada", " Okoro ")
        .await
        .expect("the write");
    let after = core.names(&id).await.expect("the read");
    assert_eq!(after.first, "Ada");
    assert_eq!(after.last, "Okoro", "names are trimmed on the way out");
}

// ── Moving accounts in ───────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn an_imported_bcrypt_hash_signs_in_with_its_original_password() {
    let core = core();
    let email = an_address();
    let user = core
        .import_password_hash(&email, BCRYPT_OF_IMPORTED, HashAlgorithm::Bcrypt)
        .await
        .expect("the import");

    let SignIn::Ok(signed_in) = core
        .sign_in(&email, IMPORTED_PASSWORD)
        .await
        .expect("the sign-in")
    else {
        panic!("the original password was refused after import");
    };
    assert_eq!(signed_in.id, user.id);
}

#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn importing_over_an_existing_address_replaces_its_password() {
    let core = core();
    let email = an_address();
    let id = signed_up(&core, &email).await;

    let user = core
        .import_password_hash(&email, BCRYPT_OF_IMPORTED, HashAlgorithm::Bcrypt)
        .await
        .expect("the import");
    assert_eq!(user.id, id, "the import made a second account");
    assert!(matches!(
        core.sign_in(&email, IMPORTED_PASSWORD)
            .await
            .expect("the sign-in"),
        SignIn::Ok(_)
    ));
}

/// Keeping another provider's ids: once mapped, the core answers with the
/// external id everywhere, so an application's `users.id` never changes.
#[tokio::test]
#[ignore = "needs a running SuperTokens core"]
async fn a_mapped_id_is_the_id_everywhere() {
    let core = core();
    let email = an_address();
    let supertokens_id = signed_up(&core, &email).await;
    let external = format!("user_{}", Uuid::new_v4().simple());

    core.map_user_id(&supertokens_id, &external)
        .await
        .expect("the mapping");

    let SignIn::Ok(user) = core.sign_in(&email, PASSWORD).await.expect("the sign-in") else {
        panic!("the password was refused after mapping");
    };
    assert_eq!(user.id, external, "sign-in answered the core's own id");

    let session = core.create_session(&external).await.expect("a session");
    let verified = verify_raw(
        &bearer(&session.access_token),
        &reqwest::Client::new(),
        &config(),
    )
    .await
    .expect("the verify call")
    .expect("the session verifies");
    assert_eq!(verified.supertokens_user_id, external);
}
