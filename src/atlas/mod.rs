use bytes::Bytes;
use http::Method;

pub mod client;
pub mod layer;
pub mod paginated;
mod version;

pub use version::Version;

pub trait Operation {
    type Response;

    fn method(&self) -> Method;
    fn url(&self) -> String;
    fn version(&self) -> Version;
    fn request_body(&self) -> Bytes {
        Bytes::new()
    }
}
