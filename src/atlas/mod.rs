use std::fmt;

use bytes::Bytes;
use http::Method;

pub use mongodb_atlas_cli_macros::operation;

pub mod client;
pub mod layer;
pub mod paginated;
mod version;

pub use layer::OperationError;
pub use version::Version;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseType {
    #[default]
    Json,
    Gzip,
}

impl fmt::Display for ResponseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseType::Json => write!(f, "json"),
            ResponseType::Gzip => write!(f, "gzip"),
        }
    }
}

pub trait Operation {
    type Response;

    fn method(&self) -> Method;
    fn url(&self) -> String;
    fn version(&self) -> Version;
    fn response_type(&self) -> ResponseType {
        ResponseType::Json
    }
    fn request_body(&self) -> Bytes {
        Bytes::new()
    }
    /// Convert raw response bytes into `Self::Response`.
    ///
    /// The macro generates this automatically:
    /// - JSON operations deserialize with `serde_json`.
    /// - Gzip / binary operations return the bytes as-is.
    fn parse_response(bytes: Bytes) -> Result<Self::Response, layer::OperationError>;
}
