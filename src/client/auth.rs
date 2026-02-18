//! Tower middleware for adding authentication to HTTP requests.
//!
//! This module implements a [`Layer`] and [`Service`] pair that intercepts
//! outgoing HTTP requests and adds the appropriate authentication headers.
//! Three authentication methods are supported:
//!
//! - **UserAccount** (OAuth2 Bearer + refresh token): Uses an access token
//!   as a Bearer token, automatically refreshing it when expired.
//! - **ServiceAccount** (OAuth2 Client Credentials): Acquires an access token
//!   using client_id/client_secret, caching it until expiry.
//! - **ApiKeys** (HTTP Digest): Performs the digest challenge-response protocol
//!   using a public/private key pair.
//!
//! # Tower Architecture
//!
//! Tower middleware uses two concepts: a [`Layer`] and a [`Service`].
//!
//! - A **Layer** is a factory: it takes an inner service and wraps it in a
//!   new service. Think of it like a constructor for middleware.
//! - A **Service** is the actual middleware: it intercepts requests, does work
//!   (in our case, adding auth headers), and forwards them to the inner service.
//!
//! ```text
//! ┌──────────────────────────┐
//! │   AuthenticationLayer    │  ← Implements Layer<S>: creates Authentication<S>
//! │ ┌──────────────────────┐ │
//! │ │  Authentication<S>   │ │  ← Implements Service: adds auth headers
//! │ │ ┌──────────────────┐ │ │
//! │ │ │  Inner Service S │ │ │  ← The actual HTTP client
//! │ │ └──────────────────┘ │ │
//! │ └──────────────────────┘ │
//! └──────────────────────────┘
//! ```
//!
//! # Token Acquisition
//!
//! When an OAuth2 token needs refreshing, the middleware clones the inner
//! service and uses it to POST to the token endpoint. This means token
//! acquisition shares the same transport (TLS, proxies, connection pool)
//! as regular API requests, and no external token acquirer is needed.
//!
//! # Shared State
//!
//! All clones of an `Authentication<S>` service share the same token cache
//! via `Arc<RwLock<AuthState>>`. This means:
//! - Concurrent requests can read the cached token in parallel (read lock).
//! - Only token refresh requires exclusive access (write lock).
//! - A token refreshed by one request is immediately available to all others.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::AUTHORIZATION;
use http::{HeaderValue, Request, Response};
use http_body::Body;
use tokio::sync::RwLock;
use tower::{Layer, Service};
use tracing::{debug, info, warn};

use crate::config::{AtlasCLIConfig, AuthType};
use crate::secrets::{Secret, SecretStore, UserAccount};

use super::digest;
use super::error::{AuthError, FromConfigError};
use super::oauth::{self, CachedToken, OAuthTokenResponse};

// ---------------------------------------------------------------------------
// Auth State
// ---------------------------------------------------------------------------

/// The mutable authentication state, protected by an [`RwLock`].
///
/// This struct is shared (via `Arc<RwLock<...>>`) between all clones of
/// the [`Authentication`] service. The RwLock allows concurrent reads
/// of the cached token while serializing writes (token refresh).
pub struct AuthState {
    pub(crate) method: AuthMethod,
}

/// The authentication method and its associated credentials/state.
///
/// Each variant carries the data needed for its specific auth flow.
/// The cached tokens are mutable (updated on refresh), while the
/// credentials themselves are fixed for the lifetime of the middleware.
pub enum AuthMethod {
    /// OAuth2 Bearer authentication with refresh token support.
    ///
    /// When the cached access token expires, the middleware uses the inner
    /// Tower service to POST to the device-flow token endpoint with
    /// `grant_type=refresh_token`, along with the Atlas CLI `client_id`
    /// and the required OAuth scopes. The new tokens are persisted to the
    /// [`SecretStore`].
    UserAccount {
        cached_token: Option<CachedToken>,
        refresh_token: String,
        token_endpoint: String,
        /// The Atlas CLI's OAuth2 client_id (public, not a secret).
        client_id: String,
        /// Used to persist refreshed tokens so they survive across CLI invocations.
        secret_store: Box<dyn SecretStore>,
        /// The CLI profile name, used as the key for the secret store.
        profile_name: String,
    },

    /// OAuth2 Bearer authentication using the client credentials grant.
    ///
    /// Acquires tokens by POSTing client_id/client_secret to the token
    /// endpoint with Basic auth credentials. Tokens are cached in memory
    /// and, when a `secret_store` is provided, persisted across process
    /// invocations so the token endpoint is not hit on every CLI run.
    ServiceAccount {
        cached_token: Option<CachedToken>,
        client_id: String,
        client_secret: String,
        token_endpoint: String,
        /// When present, acquired tokens are persisted here so they survive
        /// across process invocations (analogous to `UserAccount`).
        secret_store: Option<Box<dyn SecretStore>>,
        /// The profile name used as the key in `secret_store`.
        profile_name: Option<String>,
    },

    /// HTTP Digest authentication using API keys.
    ///
    /// Uses the challenge-response protocol: sends a probe request,
    /// gets a 401 with a nonce, computes a digest hash, and retries.
    /// No tokens are cached — each request goes through the challenge.
    ApiKeys {
        /// The public API key (used as the digest "username").
        public_key: String,
        /// The private API key (used as the digest "password").
        private_key: String,
    },
}

/// Lightweight discriminant for [`AuthMethod`].
///
/// Used to determine which auth flow to execute without holding a lock
/// on the full `AuthState` during potentially slow I/O operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMethodKind {
    UserAccount,
    ServiceAccount,
    ApiKeys,
}

impl AuthMethod {
    fn kind(&self) -> AuthMethodKind {
        match self {
            AuthMethod::UserAccount { .. } => AuthMethodKind::UserAccount,
            AuthMethod::ServiceAccount { .. } => AuthMethodKind::ServiceAccount,
            AuthMethod::ApiKeys { .. } => AuthMethodKind::ApiKeys,
        }
    }

    /// Returns a reference to the cached token, if one exists.
    /// ApiKeys auth doesn't use cached tokens, so it always returns None.
    fn cached_token(&self) -> Option<&CachedToken> {
        match self {
            AuthMethod::UserAccount { cached_token, .. }
            | AuthMethod::ServiceAccount { cached_token, .. } => cached_token.as_ref(),
            AuthMethod::ApiKeys { .. } => None,
        }
    }

    /// Clear the cached token, forcing a refresh on the next request.
    ///
    /// Used when the server rejects a token with 401 — the token may have
    /// expired server-side even though we didn't track its expiry.
    fn invalidate_token(&mut self) {
        match self {
            AuthMethod::UserAccount { cached_token, .. }
            | AuthMethod::ServiceAccount { cached_token, .. } => {
                *cached_token = None;
            }
            AuthMethod::ApiKeys { .. } => {}
        }
    }

    /// Build the token endpoint URL, form-encoded body, and optional authorization header
    /// for a token request.
    ///
    /// Returns `(endpoint_url, form_body, authorization_header)`. The form body is ready
    /// to be sent as the body of a POST request with
    /// `Content-Type: application/x-www-form-urlencoded`. The authorization header, when
    /// present, should be sent as the `Authorization` request header.
    ///
    /// For the client credentials grant (ServiceAccount), the Atlas token endpoint requires
    /// credentials in an `Authorization: Basic` header rather than the request body.
    ///
    /// Clones the necessary credential data so the request can be used
    /// after the lock is released.
    fn build_token_request(&self) -> Option<(String, String, Option<String>)> {
        match self {
            AuthMethod::UserAccount {
                refresh_token,
                token_endpoint,
                client_id,
                ..
            } => {
                let form_body = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("client_id", client_id)
                    .append_pair("refresh_token", refresh_token)
                    .append_pair("scope", "openid profile offline_access")
                    .append_pair("grant_type", "refresh_token")
                    .finish();
                Some((token_endpoint.clone(), form_body, None))
            }
            AuthMethod::ServiceAccount {
                client_id,
                client_secret,
                token_endpoint,
                ..
            } => {
                let form_body = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("grant_type", "client_credentials")
                    .finish();
                let credentials = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    format!("{client_id}:{client_secret}"),
                );
                let authorization = format!("Basic {credentials}");
                Some((token_endpoint.clone(), form_body, Some(authorization)))
            }
            AuthMethod::ApiKeys { .. } => None,
        }
    }

    /// Update the cached token after a successful refresh/acquisition.
    ///
    /// For UserAccount, also handles refresh token rotation and persists
    /// both tokens to the secret store.
    fn update_token<E>(
        &mut self,
        new_token: CachedToken,
        response: &OAuthTokenResponse,
    ) -> Result<(), AuthError<E>> {
        match self {
            AuthMethod::UserAccount {
                cached_token,
                refresh_token,
                secret_store,
                profile_name,
                ..
            } => {
                *cached_token = Some(new_token);

                // Handle token rotation: if the server issued a new refresh
                // token, replace ours. This is a security best practice that
                // limits the window during which a leaked token is usable.
                if let Some(new_refresh) = &response.refresh_token {
                    *refresh_token = new_refresh.clone();
                }

                // Persist so the refreshed tokens survive across CLI invocations.
                // Without this, the user would need to re-authenticate every
                // time they restart the CLI.
                secret_store.set(
                    profile_name,
                    Secret::UserAccount(UserAccount::new(
                        response.access_token.clone(),
                        refresh_token.clone(),
                    )),
                )?;

                Ok(())
            }
            AuthMethod::ServiceAccount {
                cached_token,
                client_id,
                client_secret,
                secret_store,
                profile_name,
                ..
            } => {
                *cached_token = Some(new_token);

                // Persist the acquired token so subsequent process invocations
                // can reuse it without hitting the token endpoint again.
                if let (Some(store), Some(name)) = (secret_store.as_mut(), profile_name.as_deref())
                {
                    store.set(
                        name,
                        Secret::ServiceAccount(crate::secrets::ServiceAccount {
                            client_id: client_id.clone(),
                            client_secret: client_secret.clone(),
                            access_token: Some(response.access_token.clone()),
                        }),
                    )?;
                }

                Ok(())
            }
            AuthMethod::ApiKeys { .. } => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Layer
// ---------------------------------------------------------------------------

/// A Tower [`Layer`] that adds authentication to HTTP requests.
///
/// Create one using the constructor for your auth type, then apply it
/// to an HTTP client via [`ServiceBuilder`](tower::ServiceBuilder):
///
/// ```rust,ignore
/// use tower::ServiceBuilder;
///
/// let auth_layer = AuthenticationLayer::api_keys(
///     "my-public-key".into(),
///     "my-private-key".into(),
/// );
///
/// let client = ServiceBuilder::new()
///     .layer(auth_layer)
///     .service(http_client);
/// ```
///
/// Token acquisition for OAuth-based auth types is handled automatically
/// by the middleware — it uses the inner service to POST to the token endpoint.
/// No external token acquirer closure is needed.
///
/// All services created by this layer share the same token cache.
#[derive(Clone)]
pub struct AuthenticationLayer {
    /// Shared mutable auth state (cached tokens, credentials, etc.).
    state: Arc<RwLock<AuthState>>,
}

impl AuthenticationLayer {
    /// Create a layer for **UserAccount** authentication.
    ///
    /// Uses OAuth2 Bearer tokens with refresh token support. When the
    /// access token expires, the middleware automatically refreshes it
    /// by POSTing the refresh token to the token endpoint via the inner
    /// Tower service.
    ///
    /// # Arguments
    ///
    /// * `access_token` - Current access token from the secret store, if any.
    ///   Pass `None` to force a refresh on the first request.
    /// * `refresh_token` - OAuth2 refresh token for acquiring new access tokens.
    /// * `token_endpoint` - URL of the OAuth2 token endpoint (see
    ///   [`Service::token_endpoint()`](crate::config::Service::token_endpoint)).
    /// * `secret_store` - Persists refreshed tokens across CLI invocations.
    /// * `profile_name` - CLI profile name (key for the secret store).
    pub fn user_account(
        access_token: Option<String>,
        refresh_token: String,
        token_endpoint: String,
        client_id: String,
        secret_store: Box<dyn SecretStore>,
        profile_name: String,
    ) -> Self {
        let cached_token = access_token.map(CachedToken::new);

        AuthenticationLayer {
            state: Arc::new(RwLock::new(AuthState {
                method: AuthMethod::UserAccount {
                    cached_token,
                    refresh_token,
                    token_endpoint,
                    client_id,
                    secret_store,
                    profile_name,
                },
            })),
        }
    }

    /// Create a layer for **ServiceAccount** authentication.
    ///
    /// Uses the OAuth2 client credentials grant. The middleware acquires
    /// a Bearer token using Basic auth credentials, then caches it until expiry.
    /// Without a secret store, the token is only cached in memory for the
    /// duration of the process. Use [`from_config`](Self::from_config) to get
    /// cross-invocation persistence via the OS keychain.
    ///
    /// # Arguments
    ///
    /// * `access_token` - A pre-existing access token to seed the cache (avoids
    ///   a token endpoint round-trip on the first request).
    /// * `client_id` / `client_secret` - OAuth2 client credentials.
    /// * `token_endpoint` - URL to POST to when acquiring or refreshing tokens.
    /// * `secret_store` - Optional store for persisting acquired tokens.
    /// * `profile_name` - Profile key for the secret store (required when
    ///   `secret_store` is `Some`).
    pub fn service_account(
        access_token: Option<String>,
        client_id: String,
        client_secret: String,
        token_endpoint: String,
        secret_store: Option<Box<dyn SecretStore>>,
        profile_name: Option<String>,
    ) -> Self {
        let cached_token = access_token.map(CachedToken::new);
        AuthenticationLayer {
            state: Arc::new(RwLock::new(AuthState {
                method: AuthMethod::ServiceAccount {
                    cached_token,
                    client_id,
                    client_secret,
                    token_endpoint,
                    secret_store,
                    profile_name,
                },
            })),
        }
    }

    /// Create a layer for **ApiKeys** (HTTP Digest) authentication.
    ///
    /// Uses the HTTP Digest challenge-response protocol. No OAuth tokens
    /// are involved — each request may trigger a 401 → digest → retry cycle.
    pub fn api_keys(public_key: String, private_key: String) -> Self {
        AuthenticationLayer {
            state: Arc::new(RwLock::new(AuthState {
                method: AuthMethod::ApiKeys {
                    public_key,
                    private_key,
                },
            })),
        }
    }

    /// Create an authentication layer automatically from the Atlas CLI config.
    ///
    /// This is the recommended constructor for CLI usage. It reads the
    /// `auth_type` from the config, looks up the matching credentials
    /// from the provided secret store, and wires everything together
    /// with the correct token endpoint.
    ///
    /// The caller is responsible for creating the secret store (via
    /// [`get_secret_store()`](crate::secrets::get_secret_store) or a
    /// custom implementation). This keeps `from_config` free of side
    /// effects and makes it easy to test with a mock store.
    ///
    /// # Arguments
    ///
    /// * `config` - The loaded CLI config (from [`load_config`](crate::config::load_config)).
    /// * `profile_name` - The CLI profile name (e.g., `"default"`).
    /// * `secret_store` - The secret store to read credentials from (and
    ///   to persist refreshed tokens into for `UserAccount` auth).
    ///
    /// # Errors
    ///
    /// Returns [`FromConfigError`] if:
    /// - `auth_type` is not set in the config
    /// - No credentials are found in the secret store for this profile
    /// - The secret type doesn't match the `auth_type`
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use mongodb_atlas_cli::{
    ///     config,
    ///     client::AuthenticationLayer,
    ///     secrets::get_secret_store,
    /// };
    ///
    /// let config = config::load_config(Some("default")).unwrap();
    /// let secret_store = get_secret_store().unwrap();
    ///
    /// let auth_layer = AuthenticationLayer::from_config(
    ///     &config,
    ///     "default",
    ///     secret_store,
    /// ).unwrap();
    /// ```
    pub fn from_config(
        config: &AtlasCLIConfig,
        profile_name: &str,
        secret_store: Box<dyn SecretStore>,
    ) -> Result<Self, FromConfigError> {
        let auth_type = config.auth_type.ok_or(FromConfigError::MissingAuthType)?;

        let secret = secret_store
            .get(profile_name, auth_type)?
            .ok_or(FromConfigError::SecretNotFound)?;

        let base_url = config.base_url();
        let client_id = config.cli_client_id();

        // Token endpoints are derived from the configured base URL so that
        // dev/staging environments work correctly.
        let user_account_token_endpoint =
            format!("{base_url}/api/private/unauth/account/device/token");
        let service_account_token_endpoint = format!("{base_url}/api/oauth/token");

        match (auth_type, secret) {
            (AuthType::UserAccount, Secret::UserAccount(ua)) => {
                debug!(
                    access_token_len = ua.access_token.len(),
                    access_token_prefix = &ua.access_token[..ua.access_token.len().min(12)],
                    refresh_token_len = ua.refresh_token.len(),
                    refresh_token_prefix = &ua.refresh_token[..ua.refresh_token.len().min(12)],
                    token_endpoint = %user_account_token_endpoint,
                    client_id = %client_id,
                    base_url = %base_url,
                    "loaded UserAccount credentials from secret store"
                );
                Ok(Self::user_account(
                    Some(ua.access_token),
                    ua.refresh_token,
                    user_account_token_endpoint,
                    client_id.to_string(),
                    secret_store,
                    profile_name.to_string(),
                ))
            }
            (AuthType::ServiceAccount, Secret::ServiceAccount(sa)) => Ok(Self::service_account(
                sa.access_token,
                sa.client_id,
                sa.client_secret,
                service_account_token_endpoint,
                Some(secret_store),
                Some(profile_name.to_string()),
            )),
            (AuthType::ApiKeys, Secret::ApiKeys(keys)) => {
                Ok(Self::api_keys(keys.public_api_key, keys.private_api_key))
            }
            // Config says one auth type, but the stored secret is a different type.
            _ => Err(FromConfigError::AuthTypeMismatch),
        }
    }
}

/// The Layer trait is Tower's factory pattern: given an inner service S,
/// produce a new service that wraps it. This is how middleware is composed
/// in a `ServiceBuilder` chain.
impl<S> Layer<S> for AuthenticationLayer {
    type Service = Authentication<S>;

    fn layer(&self, service: S) -> Self::Service {
        Authentication {
            inner: service,
            state: self.state.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Tower [`Service`] that adds authentication headers to HTTP requests.
///
/// Wraps an inner HTTP client service and intercepts each request to add
/// the appropriate auth header before forwarding.
///
/// # Clone Semantics
///
/// `Authentication<S>` is `Clone` when `S` is `Clone`. All clones share
/// the same token cache via `Arc<RwLock<...>>`, so a token refreshed by
/// one clone is immediately available to all others. This is important
/// because Tower's `ServiceBuilder` and connection pools may clone services.
#[derive(Clone)]
pub struct Authentication<S> {
    inner: S,
    state: Arc<RwLock<AuthState>>,
}

/// # Service Implementation
///
/// This is the core of the middleware. Key design decisions:
///
/// 1. **Boxed future (`Pin<Box<dyn Future>>`)**: We return a boxed future
///    because `call()` needs to do variable amounts of async work (token
///    refresh, digest challenge-response) depending on the auth method.
///    A concrete future type would need to encode all possible paths,
///    which is impractical.
///
/// 2. **Service swap pattern**: Before returning the future, we swap
///    `self.inner` with a fresh clone. The already-readied service (from
///    `poll_ready`) moves into the future, while a fresh clone replaces
///    `self.inner` for the next request. This is a standard Tower pattern
///    documented in the Tower guides.
///
/// 3. **`ReqBody: Clone`**: Required for digest auth, which may need to
///    resend the same request body after computing the digest. Types like
///    `Full<Bytes>` are cheaply cloneable (Bytes uses reference counting).
///
/// 4. **`ReqBody: From<Bytes>`**: Required for OAuth token refresh. The
///    middleware constructs a form-encoded POST body and needs to wrap it
///    in the same body type that the inner service accepts. `Full<Bytes>`
///    implements `From<Bytes>`.
///
/// 5. **Token acquisition via inner service**: When a Bearer token needs
///    refreshing, the middleware clones the inner service, readies it,
///    and uses it to POST to the token endpoint. This keeps the transport
///    consistent and avoids requiring a separate HTTP client.
impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for Authentication<S>
where
    // Clone: needed for the swap pattern, for digest (two calls to inner),
    // and for token refresh (clone inner to call token endpoint).
    // Send + 'static: needed because the future is Send and may outlive the call site.
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    // Debug: needed to format inner service errors in token refresh error messages.
    S::Error: Send + fmt::Debug,
    // Clone: needed for digest auth (replay the request body on retry).
    // From<Bytes>: needed for constructing token refresh request bodies.
    ReqBody: From<Bytes> + Clone + Send + 'static,
    ResBody: Body + Send + 'static,
    ResBody::Data: Send,
    // Debug: needed to format body collection errors in token refresh.
    ResBody::Error: Send + fmt::Debug,
{
    type Response = Response<ResBody>;
    type Error = AuthError<S::Error>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// Delegate readiness to the inner service.
    ///
    /// Tower's contract: `poll_ready` must return `Ready(Ok(()))` before
    /// `call` is invoked. We just forward to the inner service and map
    /// its error into our `AuthError` type.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(AuthError::Inner)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Clone the shared state — this is a cheap Arc reference increment.
        let state = self.state.clone();

        // --- Service Swap Pattern ---
        //
        // Tower requires that poll_ready() is called before call(). After
        // poll_ready succeeds, the service has reserved capacity for one
        // request. We need to move this "readied" service into the async
        // future, but we also need self.inner to be valid for future calls.
        //
        // Solution: clone self.inner (creating a fresh, un-readied copy),
        // then swap so the readied service goes into the future and the
        // fresh clone stays in self.inner. The caller will call poll_ready
        // again before the next call, readying the fresh clone.
        let mut inner = self.inner.clone();
        std::mem::swap(&mut self.inner, &mut inner);
        // Now: `inner` = readied service (for this request)
        //      `self.inner` = fresh clone (for future requests)

        Box::pin(async move {
            // Briefly acquire a read lock to determine the auth method.
            // We release it immediately to avoid holding the lock during
            // potentially slow network I/O.
            let method_kind = {
                let guard = state.read().await;
                guard.method.kind()
            };

            debug!(auth_method = ?method_kind, "authenticating request");

            match method_kind {
                AuthMethodKind::UserAccount | AuthMethodKind::ServiceAccount => {
                    handle_bearer_auth(state, inner, req).await
                }
                AuthMethodKind::ApiKeys => handle_digest_auth(state, inner, req).await,
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Bearer Auth Flow
// ---------------------------------------------------------------------------

/// Handle Bearer token authentication (UserAccount or ServiceAccount).
///
/// 1. Get the cached token (or refresh if expired/missing).
/// 2. Attach `Authorization: Bearer <token>` and send the request.
/// 3. If the server responds with 401, invalidate the cache, refresh
///    the token, and retry the request once.
///
/// The retry-on-401 logic handles the case where the access token has
/// expired server-side but we don't know its expiry (e.g., tokens
/// loaded from the keychain without expiry metadata).
async fn handle_bearer_auth<S, ReqBody, ResBody>(
    state: Arc<RwLock<AuthState>>,
    mut inner: S,
    req: Request<ReqBody>,
) -> Result<Response<ResBody>, AuthError<S::Error>>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Send + fmt::Debug,
    ReqBody: From<Bytes> + Clone + Send + 'static,
    ResBody: Body + Send + 'static,
    ResBody::Data: Send,
    ResBody::Error: Send + fmt::Debug,
{
    let access_token = get_or_refresh_token::<S, ReqBody, ResBody>(&state, inner.clone()).await?;

    debug!(
        token_prefix = &access_token[..access_token.len().min(8)],
        token_len = access_token.len(),
        "attaching Bearer token"
    );

    // Save request parts for a potential retry (same pattern as digest auth).
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();
    let headers = req.headers().clone();
    let body_clone = req.body().clone();

    let mut req = req;
    req.headers_mut()
        .insert(AUTHORIZATION, make_bearer_header(&access_token)?);

    let response = inner.call(req).await.map_err(AuthError::Inner)?;
    debug!(status = %response.status(), "API response received");

    if response.status() != http::StatusCode::UNAUTHORIZED {
        return Ok(response);
    }

    // --- 401 Retry Flow ---
    //
    // The server rejected our token. This typically happens when the
    // access token expired server-side but we didn't know its expiry
    // (tokens loaded from the keychain have no expiry metadata).
    // Invalidate the cache, refresh, and retry once.
    info!("received 401, refreshing token and retrying");

    {
        let mut guard = state.write().await;
        guard.method.invalidate_token();
    }

    let new_token = get_or_refresh_token::<S, ReqBody, ResBody>(&state, inner.clone()).await?;

    debug!(
        token_prefix = &new_token[..new_token.len().min(8)],
        token_len = new_token.len(),
        "retrying with refreshed token"
    );

    // Rebuild the request with the new token.
    let mut retry_req = Request::new(body_clone);
    *retry_req.method_mut() = method;
    *retry_req.uri_mut() = uri;
    *retry_req.version_mut() = version;
    *retry_req.headers_mut() = headers;
    retry_req
        .headers_mut()
        .insert(AUTHORIZATION, make_bearer_header(&new_token)?);

    std::future::poll_fn(|cx| inner.poll_ready(cx))
        .await
        .map_err(AuthError::Inner)?;

    let response = inner.call(retry_req).await.map_err(AuthError::Inner)?;
    debug!(status = %response.status(), "retry response received");
    Ok(response)
}

fn make_bearer_header<E>(token: &str) -> Result<HeaderValue, AuthError<E>> {
    HeaderValue::from_str(&format!("Bearer {token}")).map_err(|e| {
        AuthError::TokenAcquisitionFailed(format!("token contains invalid header characters: {e}"))
    })
}

/// Ensure we have a valid access token, refreshing if necessary.
///
/// This implements **double-checked locking** to minimize lock contention:
///
/// 1. **Read lock** (fast path): Check if the cached token is valid.
///    Multiple concurrent requests can do this in parallel.
/// 2. **Build token request** (read lock): Clone the credentials needed
///    for the refresh call, then release the lock.
/// 3. **HTTP call** (no lock): Ready the inner service clone and POST
///    to the token endpoint. This is the slow part, and we do it
///    without holding any lock so other requests can still read the cache.
/// 4. **Write lock** (slow path): Double-check the cache (another task
///    might have refreshed while we waited), update the cached token,
///    and persist to the secret store.
///
/// The double-check in step 4 prevents redundant refreshes: if two tasks
/// both see an expired token and both attempt to refresh, the second one
/// to acquire the write lock will find a fresh token and skip the update.
///
/// Takes an owned clone of the inner service (rather than a reference)
/// to avoid requiring `S: Sync`. The clone is only used if a token
/// refresh is actually needed.
async fn get_or_refresh_token<S, ReqBody, ResBody>(
    state: &Arc<RwLock<AuthState>>,
    mut inner: S,
) -> Result<String, AuthError<S::Error>>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Send + fmt::Debug,
    ReqBody: From<Bytes> + Send + 'static,
    ResBody: Body + Send + 'static,
    ResBody::Data: Send,
    ResBody::Error: Send + fmt::Debug,
{
    // Step 1: Fast path — check the cached token under a read lock.
    {
        let guard = state.read().await;
        if let Some(token) = guard.method.cached_token() {
            if !token.is_expired() {
                debug!(
                    expires_at = ?token.expires_at,
                    "using cached token (not expired)"
                );
                return Ok(token.access_token.clone());
            }
            debug!(expires_at = ?token.expires_at, "cached token is expired");
        } else {
            debug!("no cached token available");
        }
    } // Read lock released.

    // Step 2: Build the token request params (clone credentials while under read lock).
    let (endpoint, form_body, authorization) = {
        let guard = state.read().await;
        guard.method.build_token_request().ok_or_else(|| {
            AuthError::TokenAcquisitionFailed(
                "auth method does not support token acquisition".to_string(),
            )
        })?
    }; // Read lock released.

    info!(endpoint = %endpoint, form_body_len = form_body.len(), "refreshing OAuth token");
    debug!(form_body = %form_body, "token request body");

    // Step 3: Ready the inner service clone and call the token endpoint.
    std::future::poll_fn(|cx| inner.poll_ready(cx))
        .await
        .map_err(AuthError::Inner)?;

    let response = oauth::acquire_token(&mut inner, &endpoint, form_body, authorization)
        .await
        .map_err(|e| {
            warn!(error = %e, "token acquisition failed");
            AuthError::TokenAcquisitionFailed(e.to_string())
        })?;

    info!("token refresh successful");

    // Step 4: Write lock — update the cache and persist.
    let mut guard = state.write().await;

    // Double-check: another task might have refreshed while we were
    // making the HTTP call. If so, use their (newer) token.
    if let Some(token) = guard.method.cached_token()
        && !token.is_expired()
    {
        debug!("another task already refreshed the token");
        return Ok(token.access_token.clone());
    }

    let cached_token = CachedToken::from_response(&response);
    let access_token = cached_token.access_token.clone();
    debug!(
        expires_at = ?cached_token.expires_at,
        has_new_refresh_token = response.refresh_token.is_some(),
        "caching new token"
    );
    guard.method.update_token(cached_token, &response)?;

    Ok(access_token)
}

// ---------------------------------------------------------------------------
// Digest Auth Flow
// ---------------------------------------------------------------------------

/// Handle HTTP Digest authentication (ApiKeys).
///
/// 1. Extract credentials from state.
/// 2. Save the request parts (we'll need them to rebuild the request).
/// 3. Send a "probe" request without authentication.
/// 4. If 401 + Digest challenge:
///    a. Parse the challenge (nonce, realm, algorithm, etc.).
///    b. Compute the digest response hash.
///    c. Rebuild the request with the `Authorization: Digest ...` header.
///    d. Re-ready the inner service and send the retry.
/// 5. If not 401, return the response as-is.
async fn handle_digest_auth<S, ReqBody, ResBody>(
    state: Arc<RwLock<AuthState>>,
    mut inner: S,
    req: Request<ReqBody>,
) -> Result<Response<ResBody>, AuthError<S::Error>>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Send + 'static,
    S::Future: Send,
    S::Error: Send,
    ReqBody: Clone + Send + 'static,
    ResBody: Body + Send + 'static,
{
    // Extract credentials (read lock, released immediately).
    let (username, password) = {
        let guard = state.read().await;
        match &guard.method {
            AuthMethod::ApiKeys {
                public_key,
                private_key,
            } => (public_key.clone(), private_key.clone()),
            _ => {
                return Err(AuthError::DigestAuthFailed(
                    "expected ApiKeys auth method".to_string(),
                ));
            }
        }
    };

    // Save request parts for the retry. We can't clone Request<ReqBody>
    // directly (http::Request doesn't implement Clone), so we save the
    // individual components before the probe request consumes `req`.
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();
    let headers = req.headers().clone();
    let body_clone = req.body().clone();

    // The URI path is used in the digest hash computation.
    // path_and_query() includes the query string, which is important
    // for generating the correct digest response.
    let uri_path = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // --- Probe Request ---
    // Send the original request without authentication. The server will
    // respond with 401 + WWW-Authenticate if auth is required.
    debug!(uri = %uri, method = %method, "sending digest probe request");
    let probe_response = inner.call(req).await.map_err(AuthError::Inner)?;
    debug!(status = %probe_response.status(), "probe response received");

    // Check for a Digest challenge in the response.
    let Some(mut challenge) = digest::extract_digest_challenge(&probe_response)? else {
        debug!("no digest challenge in response, passing through");
        // Not a 401 or not a Digest challenge. The endpoint might not
        // require auth, or it uses a different auth scheme.
        return Ok(probe_response);
    };

    debug!("digest challenge received, computing response");

    // --- Compute Digest ---
    let auth_header = digest::compute_authorization_header(
        &mut challenge,
        &username,
        &password,
        method.as_str(),
        &uri_path,
    )?;

    // --- Rebuild Request ---
    // Construct a new request with the original method/uri/headers/body
    // plus the computed Authorization header.
    let mut retry_req = Request::new(body_clone);
    *retry_req.method_mut() = method;
    *retry_req.uri_mut() = uri;
    *retry_req.version_mut() = version;
    *retry_req.headers_mut() = headers;
    retry_req.headers_mut().insert(AUTHORIZATION, auth_header);

    // --- Retry ---
    // The inner service was already used for the probe request. Tower
    // services may need poll_ready() again between calls, so we re-ready
    // the service before the retry.
    std::future::poll_fn(|cx| inner.poll_ready(cx))
        .await
        .map_err(AuthError::Inner)?;

    inner.call(retry_req).await.map_err(AuthError::Inner)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::StatusCode;
    use http::header::WWW_AUTHENTICATE;
    use http_body_util::Full;
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::sync::Mutex;
    use tower::ServiceExt as _;

    use crate::secrets::{MockSecretStore, Secret};

    // -- Mock HTTP Service --

    /// Records made by the mock HTTP service for later assertion.
    #[derive(Debug)]
    #[allow(dead_code)]
    struct CapturedRequest {
        method: http::Method,
        uri: http::Uri,
        headers: http::HeaderMap,
    }

    /// A mock Tower service that returns pre-configured responses
    /// and captures incoming requests for test assertions.
    ///
    /// We use a custom mock because it's simpler for our use case:
    /// we just need a queue of responses and a record of requests.
    #[derive(Clone)]
    struct MockHttpService {
        responses: Arc<Mutex<VecDeque<Response<Full<Bytes>>>>>,
        captured_requests: Arc<Mutex<Vec<CapturedRequest>>>,
    }

    impl MockHttpService {
        fn new(responses: Vec<Response<Full<Bytes>>>) -> Self {
            MockHttpService {
                responses: Arc::new(Mutex::new(VecDeque::from(responses))),
                captured_requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Drain and return all captured requests.
        fn take_captured_requests(&self) -> Vec<CapturedRequest> {
            self.captured_requests.lock().unwrap().drain(..).collect()
        }
    }

    impl Service<Request<Full<Bytes>>> for MockHttpService {
        type Response = Response<Full<Bytes>>;
        type Error = Infallible;
        type Future =
            Pin<Box<dyn Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<Full<Bytes>>) -> Self::Future {
            self.captured_requests
                .lock()
                .unwrap()
                .push(CapturedRequest {
                    method: req.method().clone(),
                    uri: req.uri().clone(),
                    headers: req.headers().clone(),
                });

            let response = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("MockHttpService: ran out of configured responses");

            Box::pin(async move { Ok(response) })
        }
    }

    // -- Test Helpers --

    fn ok_response() -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    /// Build a mock token endpoint response with JSON body.
    fn token_endpoint_response(
        access_token: &str,
        refresh_token: Option<&str>,
        expires_in: Option<u64>,
    ) -> Response<Full<Bytes>> {
        let mut json = serde_json::json!({ "access_token": access_token });
        if let Some(rt) = refresh_token {
            json["refresh_token"] = serde_json::json!(rt);
        }
        if let Some(ei) = expires_in {
            json["expires_in"] = serde_json::json!(ei);
        }
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(serde_json::to_vec(&json).unwrap())))
            .unwrap()
    }

    fn digest_challenge_response() -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                WWW_AUTHENTICATE,
                r#"Digest realm="test@example.org", qop="auth", algorithm=MD5, nonce="test-nonce-123", opaque="test-opaque""#,
            )
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    fn get_request(uri: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    // -- Bearer Auth Tests --

    #[tokio::test]
    async fn bearer_with_valid_cached_token_skips_refresh() {
        let layer = AuthenticationLayer {
            state: Arc::new(RwLock::new(AuthState {
                method: AuthMethod::UserAccount {
                    cached_token: Some(CachedToken::new("cached-access-token".into())),
                    refresh_token: "test-refresh-token".into(),
                    token_endpoint: "https://example.com/token".into(),
                    client_id: "test-client-id".into(),
                    secret_store: Box::new(MockSecretStore::new()),
                    profile_name: "default".into(),
                },
            })),
        };

        // Only one response needed — no token refresh, just the API call.
        let mock_svc = MockHttpService::new(vec![ok_response()]);
        let mut svc = layer.layer(mock_svc.clone());

        let response = svc
            .ready()
            .await
            .unwrap()
            .call(get_request("http://api.example.com/test"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let captured = mock_svc.take_captured_requests();
        assert_eq!(
            captured.len(),
            1,
            "expected only the API request, no token refresh"
        );
        assert_eq!(
            captured[0].headers.get(AUTHORIZATION).unwrap(),
            "Bearer cached-access-token"
        );
    }

    #[tokio::test]
    async fn bearer_refreshes_expired_token_and_persists() {
        let expired_token = CachedToken {
            access_token: "old-token".into(),
            expires_at: Some(std::time::Instant::now() - std::time::Duration::from_secs(60)),
        };

        let mut mock_store = MockSecretStore::new();
        mock_store
            .expect_set()
            .withf(|profile, secret| {
                profile == "default"
                    && match secret {
                        Secret::UserAccount(ua) => {
                            ua.access_token == "new-access-token"
                                && ua.refresh_token == "new-refresh-token"
                        }
                        _ => false,
                    }
            })
            .times(1)
            .returning(|_, _| Ok(()));

        let layer = AuthenticationLayer {
            state: Arc::new(RwLock::new(AuthState {
                method: AuthMethod::UserAccount {
                    cached_token: Some(expired_token),
                    refresh_token: "old-refresh-token".into(),
                    token_endpoint: "https://example.com/token".into(),
                    client_id: "test-client-id".into(),
                    secret_store: Box::new(mock_store),
                    profile_name: "default".into(),
                },
            })),
        };

        // Two responses: first for token refresh, then for the API call.
        let mock_svc = MockHttpService::new(vec![
            token_endpoint_response("new-access-token", Some("new-refresh-token"), Some(3600)),
            ok_response(),
        ]);
        let mut svc = layer.layer(mock_svc.clone());

        let response = svc
            .ready()
            .await
            .unwrap()
            .call(get_request("http://api.example.com/test"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let captured = mock_svc.take_captured_requests();
        assert_eq!(captured.len(), 2, "expected token refresh + API request");

        // First request: POST to token endpoint.
        assert_eq!(captured[0].method, http::Method::POST);
        assert_eq!(captured[0].uri, "https://example.com/token");

        // Second request: GET to API with the new Bearer token.
        assert_eq!(
            captured[1].headers.get(AUTHORIZATION).unwrap(),
            "Bearer new-access-token"
        );
    }

    #[tokio::test]
    async fn bearer_acquires_token_when_none_cached() {
        let mut mock_store = MockSecretStore::new();
        mock_store.expect_set().times(1).returning(|_, _| Ok(()));

        let layer = AuthenticationLayer {
            state: Arc::new(RwLock::new(AuthState {
                method: AuthMethod::UserAccount {
                    cached_token: None,
                    refresh_token: "my-refresh-token".into(),
                    token_endpoint: "https://example.com/token".into(),
                    client_id: "test-client-id".into(),
                    secret_store: Box::new(mock_store),
                    profile_name: "default".into(),
                },
            })),
        };

        // Two responses: token refresh + API call.
        let mock_svc = MockHttpService::new(vec![
            token_endpoint_response("fresh-token", None, Some(3600)),
            ok_response(),
        ]);
        let mut svc = layer.layer(mock_svc.clone());

        let response = svc
            .ready()
            .await
            .unwrap()
            .call(get_request("http://api.example.com/test"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let captured = mock_svc.take_captured_requests();
        assert_eq!(captured.len(), 2);
        assert_eq!(
            captured[1].headers.get(AUTHORIZATION).unwrap(),
            "Bearer fresh-token"
        );
    }

    // -- Client Credentials Tests --

    #[tokio::test]
    async fn client_credentials_acquires_token_when_none_cached() {
        let layer = AuthenticationLayer {
            state: Arc::new(RwLock::new(AuthState {
                method: AuthMethod::ServiceAccount {
                    cached_token: None,
                    client_id: "my-client-id".into(),
                    client_secret: "my-client-secret".into(),
                    token_endpoint: "https://example.com/token".into(),
                    secret_store: None,
                    profile_name: None,
                },
            })),
        };

        // Two responses: token acquisition + API call.
        let mock_svc = MockHttpService::new(vec![
            token_endpoint_response("service-token", None, Some(3600)),
            ok_response(),
        ]);
        let mut svc = layer.layer(mock_svc.clone());

        let response = svc
            .ready()
            .await
            .unwrap()
            .call(get_request("http://api.example.com/test"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let captured = mock_svc.take_captured_requests();
        assert_eq!(captured.len(), 2);

        // First request: POST to token endpoint with client credentials.
        assert_eq!(captured[0].method, http::Method::POST);
        assert_eq!(captured[0].uri, "https://example.com/token");

        // Second request: GET to API with the acquired Bearer token.
        assert_eq!(
            captured[1].headers.get(AUTHORIZATION).unwrap(),
            "Bearer service-token"
        );
    }

    #[tokio::test]
    async fn client_credentials_reuses_valid_cached_token() {
        let layer = AuthenticationLayer {
            state: Arc::new(RwLock::new(AuthState {
                method: AuthMethod::ServiceAccount {
                    cached_token: Some(CachedToken::new("cached-service-token".into())),
                    client_id: "my-client-id".into(),
                    client_secret: "my-client-secret".into(),
                    token_endpoint: "https://example.com/token".into(),
                    secret_store: None,
                    profile_name: None,
                },
            })),
        };

        // Only one response — no token refresh needed.
        let mock_svc = MockHttpService::new(vec![ok_response()]);
        let mut svc = layer.layer(mock_svc.clone());

        let response = svc
            .ready()
            .await
            .unwrap()
            .call(get_request("http://api.example.com/test"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let captured = mock_svc.take_captured_requests();
        assert_eq!(captured.len(), 1, "expected only the API request");
        assert_eq!(
            captured[0].headers.get(AUTHORIZATION).unwrap(),
            "Bearer cached-service-token"
        );
    }

    // -- Digest Auth Tests --

    #[tokio::test]
    async fn digest_handles_challenge_response_flow() {
        let layer = AuthenticationLayer::api_keys("my-public-key".into(), "my-private-key".into());

        // First response: 401 with digest challenge
        // Second response: 200 OK (after successful digest auth)
        let mock_svc = MockHttpService::new(vec![digest_challenge_response(), ok_response()]);
        let mut svc = layer.layer(mock_svc.clone());

        let response = svc
            .ready()
            .await
            .unwrap()
            .call(get_request("http://api.example.com/api/atlas/v2/groups"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let captured = mock_svc.take_captured_requests();
        assert_eq!(captured.len(), 2, "expected probe + retry");

        // Probe request should have no Authorization header.
        assert!(
            captured[0].headers.get(AUTHORIZATION).is_none(),
            "probe should not have Authorization header"
        );

        // Retry request should have a Digest Authorization header.
        let auth_header = captured[1]
            .headers
            .get(AUTHORIZATION)
            .expect("retry should have Authorization header");
        let auth_str = auth_header.to_str().unwrap();
        assert!(
            auth_str.starts_with("Digest "),
            "expected Digest auth, got: {auth_str}"
        );
        assert!(
            auth_str.contains("username=\"my-public-key\""),
            "expected username in digest header, got: {auth_str}"
        );
    }

    #[tokio::test]
    async fn digest_passes_through_non_401_response() {
        let layer = AuthenticationLayer::api_keys("my-public-key".into(), "my-private-key".into());

        let mock_svc = MockHttpService::new(vec![ok_response()]);
        let mut svc = layer.layer(mock_svc.clone());

        let response = svc
            .ready()
            .await
            .unwrap()
            .call(get_request("http://api.example.com/test"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let captured = mock_svc.take_captured_requests();
        assert_eq!(captured.len(), 1, "should not retry for non-401");
    }

    #[tokio::test]
    async fn digest_passes_through_401_without_digest_scheme() {
        // Server returns 401 but with Basic auth, not Digest.
        let basic_401 = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(WWW_AUTHENTICATE, "Basic realm=\"test\"")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let layer = AuthenticationLayer::api_keys("my-public-key".into(), "my-private-key".into());

        let mock_svc = MockHttpService::new(vec![basic_401]);
        let mut svc = layer.layer(mock_svc.clone());

        let response = svc
            .ready()
            .await
            .unwrap()
            .call(get_request("http://api.example.com/test"))
            .await
            .unwrap();

        // Should pass through the 401 since it's not a Digest challenge.
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let captured = mock_svc.take_captured_requests();
        assert_eq!(captured.len(), 1, "should not retry for non-Digest 401");
    }

    // -- Error Handling Tests --

    #[tokio::test]
    async fn token_acquisition_failure_returns_error() {
        let mut mock_store = MockSecretStore::new();
        // set() should never be called since acquisition fails.
        mock_store.expect_set().never();

        let layer = AuthenticationLayer {
            state: Arc::new(RwLock::new(AuthState {
                method: AuthMethod::UserAccount {
                    cached_token: None,
                    refresh_token: "my-refresh-token".into(),
                    token_endpoint: "https://example.com/token".into(),
                    client_id: "test-client-id".into(),
                    secret_store: Box::new(mock_store),
                    profile_name: "default".into(),
                },
            })),
        };

        // Return a 400 error from the token endpoint.
        let error_response = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from(r#"{"error":"invalid_grant"}"#)))
            .unwrap();

        let mock_svc = MockHttpService::new(vec![error_response]);
        let mut svc = layer.layer(mock_svc);

        let result = svc
            .ready()
            .await
            .unwrap()
            .call(get_request("http://api.example.com/test"))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, AuthError::TokenAcquisitionFailed(msg) if msg.contains("400")),
            "expected TokenAcquisitionFailed with status 400, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn digest_malformed_challenge_returns_error() {
        let malformed_response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(WWW_AUTHENTICATE, "Digest this-is-not-valid")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let layer = AuthenticationLayer::api_keys("my-public-key".into(), "my-private-key".into());

        let mock_svc = MockHttpService::new(vec![malformed_response]);
        let mut svc = layer.layer(mock_svc);

        let result = svc
            .ready()
            .await
            .unwrap()
            .call(get_request("http://api.example.com/test"))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, AuthError::DigestAuthFailed(_)),
            "expected DigestAuthFailed, got: {err:?}"
        );
    }

    // -- from_config Tests --

    #[tokio::test]
    async fn from_config_creates_user_account_layer() {
        use crate::config::{AtlasCLIConfig, AuthType};

        let mut mock_store = MockSecretStore::new();
        mock_store
            .expect_get()
            .withf(|profile, auth_type| profile == "default" && *auth_type == AuthType::UserAccount)
            .times(1)
            .returning(|_, _| {
                Ok(Some(Secret::UserAccount(UserAccount::new(
                    "my-access-token".into(),
                    "my-refresh-token".into(),
                ))))
            });

        let config = AtlasCLIConfig {
            auth_type: Some(AuthType::UserAccount),
            ..Default::default()
        };

        let layer = AuthenticationLayer::from_config(&config, "default", Box::new(mock_store))
            .expect("from_config should succeed");

        // Verify the layer produces a working service with a cached token.
        let mock_svc = MockHttpService::new(vec![ok_response()]);
        let mut svc = layer.layer(mock_svc.clone());

        let response = svc
            .ready()
            .await
            .unwrap()
            .call(get_request("http://api.example.com/test"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let captured = mock_svc.take_captured_requests();
        assert_eq!(captured.len(), 1);
        assert_eq!(
            captured[0].headers.get(AUTHORIZATION).unwrap(),
            "Bearer my-access-token"
        );
    }
}
