use bytes::Bytes;
use http::Method;
use url::Url;

use crate::atlas::version::Version;

mod operations;
mod version;

pub trait Operation {
    type Response;
    
    fn method(&self) -> Method;
    fn url(&self) -> Url;
    fn version(&self) -> Version;
    fn body(&self) -> Bytes;
}

