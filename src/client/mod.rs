//! HTTP client with authentication middleware.
//!
//! This module provides a Tower-based HTTP client with pluggable authentication.
//! The main components are:
//!
//! - [`AuthenticationLayer`] / [`Authentication`]: Tower middleware that adds
//!   auth headers to outgoing requests. Supports three auth methods:
//!   - **UserAccount**: OAuth2 Bearer + refresh token
//!   - **ServiceAccount**: OAuth2 client credentials grant
//!   - **ApiKeys**: HTTP Digest authentication
//!
//! - [`AuthError`]: Error type for authentication failures.
//!
//! - [`OAuthTokenResponse`]: The parsed response from an OAuth2 token endpoint.
//!
//! Token acquisition is handled internally by the middleware — it uses the
//! inner Tower service to POST to the token endpoint, so no separate HTTP
//! client or closure is needed.
//!
//! # Example
//!
//! ```rust,ignore
//! use tower::ServiceBuilder;
//! use mongodb_atlas_cli::client::AuthenticationLayer;
//!
//! // Digest auth (ApiKeys) — simplest setup, no token endpoint needed.
//! let auth_layer = AuthenticationLayer::api_keys(
//!     "my-public-key".into(),
//!     "my-private-key".into(),
//! );
//!
//! let client = ServiceBuilder::new()
//!     .layer(auth_layer)
//!     .service(http_client);
//! ```

pub mod auth;
pub mod digest;
pub mod error;
pub mod oauth;

pub use auth::{AuthMethod, Authentication, AuthenticationLayer};
pub use error::{AuthError, FromConfigError};
pub use oauth::{CachedToken, OAuthError, OAuthTokenResponse};
