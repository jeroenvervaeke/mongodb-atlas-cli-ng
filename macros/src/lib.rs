//! Procedural macros for `mongodb-atlas-cli`: `#[operation]` attribute to generate
//! `Operation` trait implementations from declarative request structs.

mod model;
mod parse;
mod render;

use proc_macro::TokenStream;
use syn::parse_macro_input;

/// Generates an `Operation` implementation and related types from a request struct.
///
/// Requires companion attributes:
/// - `#[url("/path/{param}/...")]` — URL template with optional `{param}` placeholders
/// - `#[response(Type)]` or `#[response(paginated, Type)]` — JSON response; `paginated` = list endpoint
/// - `#[response(gzip)]` — binary (gzip) download; response type is always `bytes::Bytes`
///
/// Example:
///
/// ```ignore
/// #[operation(method = GET, version = "2024-08-05")]
/// #[url("/api/atlas/v2/groups/{group_id}/clusters")]
/// #[response(paginated, ListGroupClusterResponse)]
/// struct ListGroupClusterRequest {}
/// ```
#[proc_macro_attribute]
pub fn operation(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as syn::ItemStruct);
    let parsed = match parse::parse(attr.into(), item.clone()) {
        Ok(p) => p,
        Err(e) => return e.into_compile_error().into(),
    };
    let code = model::GeneratedCode::from_parsed(parsed);
    render::render(&code, &item).into()
}
