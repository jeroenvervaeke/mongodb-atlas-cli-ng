use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Full};
use serde::{Deserialize, de::DeserializeOwned};
use tower::{Layer, Service};

use super::Operation;
use crate::config::AtlasCLIConfig;

/// Error body returned by the Atlas Admin API on non-2xx responses.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AtlasApiError {
    pub detail: Option<String>,
    pub error: Option<u16>,
    pub error_code: Option<String>,
    pub reason: Option<String>,
}

impl fmt::Display for AtlasApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = &self.error_code {
            write!(f, "[{code}] ")?;
        }
        if let Some(detail) = &self.detail {
            write!(f, "{detail}")?;
        } else if let Some(reason) = &self.reason {
            write!(f, "{reason}")?;
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum OperationError {
    #[error("atlas API error (HTTP {status}): {error}")]
    Atlas {
        status: StatusCode,
        error: AtlasApiError,
    },

    #[error("non-success response (HTTP {status}) with unparseable body: {body}")]
    UnexpectedStatus { status: StatusCode, body: String },

    #[error("service error: {0}")]
    Service(Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to collect response body: {0}")]
    Body(Box<dyn std::error::Error + Send + Sync>),

    #[error("response deserialization failed: {0}")]
    Deserialize(#[from] serde_json::Error),

    #[error("failed to build HTTP request: {0}")]
    BuildRequest(http::Error),
}

/// Tower [`Layer`] that converts [`Operation`] implementors into HTTP requests,
/// sends them through the inner service, and deserializes the response body
/// into `Operation::Response`.
#[derive(Clone)]
pub struct OperationLayer {
    config: AtlasCLIConfig,
}

impl OperationLayer {
    pub fn new(config: AtlasCLIConfig) -> Self {
        Self { config }
    }
}

impl<S: Clone> Layer<S> for OperationLayer {
    type Service = OperationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OperationService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Tower [`Service`] that accepts any [`Operation`] and returns `Operation::Response`.
///
/// For each incoming operation it:
/// 1. Joins the config's `base_url` with the operation's path
/// 2. Builds an HTTP request with the correct method, `Accept` header, and body
/// 3. Forwards the request to the inner service
/// 4. Deserializes the JSON response body into `Operation::Response`
#[derive(Clone)]
pub struct OperationService<S> {
    inner: S,
    config: AtlasCLIConfig,
}

impl<S, O, ResBody> Service<O> for OperationService<S>
where
    O: Operation + Send + 'static,
    O::Response: DeserializeOwned,
    S: Service<Request<Full<Bytes>>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    S::Future: Send,
    ResBody: Body + Send + 'static,
    ResBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ResBody::Data: Send,
{
    type Response = O::Response;
    type Error = OperationError;
    type Future = Pin<Box<dyn Future<Output = Result<O::Response, OperationError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|e| OperationError::Service(e.into()))
    }

    fn call(&mut self, op: O) -> Self::Future {
        let uri = format!("{}{}", self.config.base_url(), op.url());
        let clone = self.inner.clone();
        let ready = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let accept = format!("{}+json", op.version());

            let request = Request::builder()
                .method(op.method())
                .uri(uri)
                .header(http::header::ACCEPT, accept)
                .body(Full::new(op.body()))
                .map_err(OperationError::BuildRequest)?;

            let mut inner = ready;
            let response = inner
                .call(request)
                .await
                .map_err(|e| OperationError::Service(e.into()))?;

            let status = response.status();
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|e| OperationError::Body(e.into()))?
                .to_bytes();

            if !status.is_success() {
                return Err(match serde_json::from_slice::<AtlasApiError>(&body) {
                    Ok(error) => OperationError::Atlas { status, error },
                    Err(_) => OperationError::UnexpectedStatus {
                        status,
                        body: String::from_utf8_lossy(&body).into_owned(),
                    },
                });
            }

            serde_json::from_slice(&body).map_err(OperationError::Deserialize)
        })
    }
}
