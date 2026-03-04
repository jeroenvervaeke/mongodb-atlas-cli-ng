use bytes::Bytes;
use http::Method;

use crate::atlas::version::Version;

pub mod layer;
pub mod operations;
pub mod paginated;
mod version;

pub trait Operation {
    type Response;

    fn method(&self) -> Method;
    fn url(&self) -> String;
    fn version(&self) -> Version;
    fn body(&self) -> Bytes;
}
