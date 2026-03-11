//! Parses `#[operation]`, `#[url]`, and `#[response]` attributes from a struct into an IR.

use quote::ToTokens;
use syn::{parse::Parse, parse2, Attribute, Ident, ItemStruct, Lit, Meta, Path, Token};

/// Intermediate representation after parsing the struct and its attributes.
#[derive(Debug, Clone)]
pub struct ParsedInput {
    pub struct_name: String,
    pub method: String,
    pub version_str: String,
    pub url_template: String,
    pub url_param_names: Vec<String>,
    pub is_paginated: bool,
    pub response_type: String,
    /// "json" (default) or "gzip"
    pub response_format: String,
}

/// Extract URL parameter names from a template string, e.g. "/groups/{group_id}/x" -> ["group_id"].
pub fn extract_url_param_names(template: &str) -> Vec<String> {
    let mut params = Vec::new();
    let mut chars = template.chars();
    while let Some(c) = chars.next() {
        if c == '{' {
            let param: String = chars.by_ref().take_while(|&c| c != '}').collect();
            params.push(param);
        }
    }
    params
}

fn parse_url_attr(attr: &Attribute) -> Option<String> {
    let Meta::List(list) = attr.meta.clone() else {
        return None;
    };
    if !list.path.is_ident("url") {
        return None;
    }
    let lit: Lit = syn::parse2(list.tokens).ok()?;
    if let Lit::Str(s) = lit {
        return Some(s.value());
    }
    None
}

/// Returns `(is_paginated, response_type, response_format)`.
///
/// The `#[response]` attribute accepts an optional comma-separated list of modifiers
/// (`paginated`, `gzip`) followed by the response type:
///   - `#[response(TypeName)]`
///   - `#[response(paginated, TypeName)]`
///   - `#[response(gzip, bytes::Bytes)]`
fn parse_response_attr(attr: &Attribute) -> Option<(bool, String, String)> {
    let Meta::List(list) = attr.meta.clone() else {
        return None;
    };
    if !list.path.is_ident("response") {
        return None;
    }
    struct ResponseArgs {
        paths: Vec<Path>,
    }
    impl Parse for ResponseArgs {
        fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
            let mut paths = Vec::new();
            while !input.is_empty() {
                paths.push(input.parse::<Path>()?);
                if input.peek(Token![,]) {
                    input.parse::<Token![,]>()?;
                }
            }
            Ok(ResponseArgs { paths })
        }
    }
    let args: ResponseArgs = parse2(list.tokens).ok()?;
    let is_paginated = args.paths.iter().any(|p| p.is_ident("paginated"));
    let is_gzip = args.paths.iter().any(|p| p.is_ident("gzip"));
    // The response type is the last path that isn't a known modifier keyword.
    // Gzip responses always use `bytes::Bytes`; an explicit type is not required.
    let response_type = args
        .paths
        .iter()
        .rfind(|p| !p.is_ident("paginated") && !p.is_ident("gzip"))
        .map(|p| p.to_token_stream().to_string())
        .unwrap_or_else(|| {
            if is_gzip {
                "bytes::Bytes".to_string()
            } else {
                String::new()
            }
        });
    let response_format = if is_gzip { "gzip" } else { "json" }.to_string();
    Some((is_paginated, response_type, response_format))
}

struct OperationAttrArgs {
    args: Vec<OperationAttrArg>,
}

enum OperationAttrArg {
    Method(String),
    Version(String),
}

impl Parse for OperationAttrArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut args = Vec::new();
        while !input.is_empty() {
            let name: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            if name == "method" {
                let path: Path = input.parse()?;
                let method = path
                    .get_ident()
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| path.to_token_stream().to_string());
                args.push(OperationAttrArg::Method(method));
            } else if name == "version" {
                let lit: Lit = input.parse()?;
                let version = match &lit {
                    Lit::Str(s) => s.value(),
                    _ => return Err(input.error("version must be a string literal")),
                };
                args.push(OperationAttrArg::Version(version));
            } else {
                return Err(input.error("unknown operation attribute"));
            }
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        Ok(OperationAttrArgs { args })
    }
}

/// Parse the operation attribute args (from the invoking attribute) and the item into `ParsedInput`.
pub fn parse(attr: proc_macro2::TokenStream, item: ItemStruct) -> syn::Result<ParsedInput> {
    let struct_name = item.ident.to_string();
    let (method, version_str) = parse_operation_args(attr)?;

    let mut url_template = None;
    let mut is_paginated = None;
    let mut response_type = None;
    let mut response_format = None;

    for attr in &item.attrs {
        if let Some(url) = parse_url_attr(attr) {
            url_template = Some(url);
        }
        if let Some((pag, ty, fmt)) = parse_response_attr(attr) {
            is_paginated = Some(pag);
            response_type = Some(ty);
            response_format = Some(fmt);
        }
    }

    let url_template = url_template
        .ok_or_else(|| syn::Error::new_spanned(&item.ident, "missing #[url(\"...\")]"))?;
    let is_paginated = is_paginated
        .ok_or_else(|| syn::Error::new_spanned(&item.ident, "missing #[response(...)]"))?;
    let response_type = response_type.ok_or_else(|| {
        syn::Error::new_spanned(&item.ident, "missing response type in #[response]")
    })?;
    let response_format = response_format.unwrap_or_else(|| "json".to_string());

    let url_param_names = extract_url_param_names(&url_template);

    Ok(ParsedInput {
        struct_name,
        method,
        version_str,
        url_template,
        url_param_names,
        is_paginated,
        response_type,
        response_format,
    })
}

/// Parse the token stream from #[operation(...)] into method and version.
fn parse_operation_args(attr: proc_macro2::TokenStream) -> syn::Result<(String, String)> {
    let args = syn::parse2::<OperationAttrArgs>(attr)?;
    let mut method = None;
    let mut version = None;
    for arg in args.args {
        match arg {
            OperationAttrArg::Method(m) => method = Some(m),
            OperationAttrArg::Version(v) => version = Some(v),
        }
    }
    let span = proc_macro2::Span::call_site();
    let method =
        method.ok_or_else(|| syn::Error::new(span, "missing method = ... in #[operation]"))?;
    let version_str = version
        .ok_or_else(|| syn::Error::new(span, "missing version = \"...\" in #[operation]"))?;
    Ok((method, version_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_url_params_empty() {
        assert!(extract_url_param_names("/api/foo").is_empty());
    }

    #[test]
    fn extract_url_params_single() {
        assert_eq!(
            extract_url_param_names("/api/groups/{group_id}/clusters"),
            vec!["group_id"]
        );
    }

    #[test]
    fn extract_url_params_multiple() {
        assert_eq!(
            extract_url_param_names("/groups/{group_id}/clusters/{cluster_id}"),
            vec!["group_id", "cluster_id"]
        );
    }
}
