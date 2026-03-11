//! Renders `GeneratedCode` and the original struct into a `TokenStream`.

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::parse_str;

use crate::model::{GeneratedCode, GeneratedOperationImpl, GeneratedStruct, VersionKind};

fn strip_consumed_attrs(attrs: &[syn::Attribute]) -> Vec<syn::Attribute> {
    attrs
        .iter()
        .filter(|a| {
            !(a.path().is_ident("operation")
                || a.path().is_ident("url")
                || a.path().is_ident("response"))
        })
        .cloned()
        .collect()
}

fn path_from_type_string(s: &str) -> syn::Type {
    if s == "PaginationRequest" {
        parse_str::<syn::Type>("::mongodb_atlas_cli::atlas::paginated::PaginationRequest")
            .expect("PaginationRequest path is valid")
    } else {
        parse_str::<syn::Type>(s).unwrap_or_else(|_| parse_str("()").unwrap())
    }
}

fn version_to_tokens(v: &VersionKind) -> TokenStream {
    match v {
        VersionKind::Date { year, month, day } => {
            quote! { ::mongodb_atlas_cli::atlas::Version::date(#year, #month, #day) }
        }
        VersionKind::Preview => quote! { ::mongodb_atlas_cli::atlas::Version::preview() },
        VersionKind::Upcoming { year, month, day } => {
            quote! { ::mongodb_atlas_cli::atlas::Version::upcoming(#year, #month, #day) }
        }
    }
}

/// Extract `#[derive(...)]` attributes from the original struct to forward onto generated types.
/// Falls back to `#[derive(Debug)]` when the original has no derives.
fn extract_derive_attrs(attrs: &[syn::Attribute]) -> TokenStream {
    let derives: Vec<_> = attrs
        .iter()
        .filter(|a| a.path().is_ident("derive"))
        .collect();
    if derives.is_empty() {
        quote! { #[derive(Debug)] }
    } else {
        quote! { #(#derives)* }
    }
}

/// Emit the operation struct, forwarding the derive attributes from the original struct.
/// `TypedBuilder` is always added so callers get a builder for free.
fn emit_operation_struct(s: &GeneratedStruct, derive_attrs: TokenStream) -> TokenStream {
    let name = syn::Ident::new(&s.name, proc_macro2::Span::call_site());
    let fields = s.fields.iter().map(|f| {
        let fname = syn::Ident::new(&f.name, proc_macro2::Span::call_site());
        let fty = path_from_type_string(&f.ty);
        let vis = if f.is_public {
            quote! { pub }
        } else {
            quote! {}
        };
        let builder_attr = if f.builder_default {
            quote! { #[builder(default)] }
        } else {
            quote! {}
        };
        quote! { #builder_attr #vis #fname: #fty }
    });
    quote! {
        #derive_attrs
        #[derive(::typed_builder::TypedBuilder)]
        pub struct #name {
            #(#fields),*
        }
    }
}

fn emit_url_params_struct(s: &GeneratedStruct) -> TokenStream {
    let name = syn::Ident::new(&s.name, proc_macro2::Span::call_site());
    let fields = s.fields.iter().map(|f| {
        let fname = syn::Ident::new(&f.name, proc_macro2::Span::call_site());
        quote! { pub #fname: String }
    });
    quote! {
        #[derive(Debug, Default, Clone, PartialEq, Eq)]
        #[derive(::typed_builder::TypedBuilder)]
        pub struct #name {
            #(#fields),*
        }
    }
}

fn emit_operation_impl(impl_: &GeneratedOperationImpl) -> TokenStream {
    let struct_name = syn::Ident::new(&impl_.struct_name, proc_macro2::Span::call_site());
    let method = syn::Ident::new(&impl_.method, proc_macro2::Span::call_site());
    let response_type = path_from_type_string(&impl_.response_type);
    let version = version_to_tokens(&impl_.version);

    let response_ty = if impl_.is_paginated {
        quote! { ::mongodb_atlas_cli::atlas::paginated::PaginatedResponse<#response_type> }
    } else {
        quote! { #response_type }
    };

    let format_args: Vec<_> = impl_
        .url_param_names
        .iter()
        .map(|n| {
            let id = syn::Ident::new(n, proc_macro2::Span::call_site());
            quote! { self.url_parameters.#id }
        })
        .collect();
    let url_format_lit = syn::LitStr::new(&impl_.url_format_string, proc_macro2::Span::call_site());

    let url_body = if impl_.url_param_names.is_empty() {
        if impl_.is_paginated {
            quote! {
                let mut url = #url_format_lit.to_string();
                self.pagination.append_to(&mut url);
                url
            }
        } else {
            quote! {
                #url_format_lit.to_string()
            }
        }
    } else if impl_.is_paginated {
        quote! {
            let mut url = format!(#url_format_lit, #(#format_args),*);
            self.pagination.append_to(&mut url);
            url
        }
    } else {
        quote! {
            format!(#url_format_lit, #(#format_args),*)
        }
    };

    quote! {
        impl ::mongodb_atlas_cli::atlas::Operation for #struct_name {
            type Response = #response_ty;

            fn method(&self) -> ::http::Method {
                ::http::Method::#method
            }

            fn url(&self) -> String {
                #url_body
            }

            fn version(&self) -> ::mongodb_atlas_cli::atlas::Version {
                #version
            }
        }
    }
}

/// Format rendered token stream as a string for snapshot testing.
#[cfg(test)]
pub fn render_to_formatted_string(code: &GeneratedCode, original: &syn::ItemStruct) -> String {
    let tokens = render(code, original);
    // Wrap in a mod so we have a single parseable item (File expects top-level items).
    let wrapped = quote::quote! {
        mod __generated {
            #tokens
        }
    };
    let file = syn::parse2::<syn::File>(wrapped).expect("generated code should be valid Rust");
    prettyplease::unparse(&file)
}

/// Produce the full token stream: original struct (with attrs stripped, if body is used), url params struct (if any), operation struct, impl.
pub fn render(code: &GeneratedCode, original: &syn::ItemStruct) -> TokenStream {
    let derive_attrs = extract_derive_attrs(&original.attrs);
    let url_params_blocks: Vec<_> = code
        .url_params_struct
        .as_ref()
        .map(emit_url_params_struct)
        .into_iter()
        .collect();
    let operation_struct = emit_operation_struct(&code.operation_struct, derive_attrs);
    let operation_impl = emit_operation_impl(&code.operation_impl);

    let mut item = original.clone();
    item.attrs = strip_consumed_attrs(&original.attrs);

    if !code.has_body {
        // For GET/DELETE there is no body field referencing this struct, so inject
        // #[allow(dead_code)] into the generated output so the user can still
        // derive traits without seeing a dead_code warning in their own source.
        let allow_dead_code: syn::Attribute = syn::parse_quote!(#[allow(dead_code)]);
        item.attrs.insert(0, allow_dead_code);
    }

    let original_struct = item.to_token_stream();

    quote! {
        #original_struct

        #( #url_params_blocks )*

        #operation_struct

        #operation_impl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GeneratedCode;
    use crate::parse::ParsedInput;

    fn parsed(
        struct_name: &str,
        method: &str,
        version: &str,
        url_template: &str,
        is_paginated: bool,
        response_type: &str,
    ) -> ParsedInput {
        ParsedInput {
            struct_name: struct_name.to_string(),
            method: method.to_string(),
            version_str: version.to_string(),
            url_template: url_template.to_string(),
            url_param_names: crate::parse::extract_url_param_names(url_template),
            is_paginated,
            response_type: response_type.to_string(),
        }
    }

    fn minimal_struct(name: &str) -> syn::ItemStruct {
        syn::parse_str(&format!(
            "#[derive(Debug, Clone, PartialEq, Eq)] struct {} {{}}",
            name
        ))
        .expect("valid struct")
    }

    #[test]
    fn snapshot_get_group_cluster() {
        let ir = parsed(
            "GetGroupClusterRequest",
            "GET",
            "2024-08-05",
            "/api/atlas/v2/groups/{group_id}/clusters/{cluster_name}",
            false,
            "ClusterDescription20240805",
        );
        let code = GeneratedCode::from_parsed(ir);
        let original = minimal_struct("GetGroupClusterRequest");
        let formatted = render_to_formatted_string(&code, &original);
        insta::assert_snapshot!(formatted);
    }

    #[test]
    fn snapshot_list_group_clusters() {
        let ir = parsed(
            "ListGroupClustersRequest",
            "GET",
            "2024-08-05",
            "/api/atlas/v2/groups/{group_id}/clusters",
            true,
            "ClusterDescription20240805",
        );
        let code = GeneratedCode::from_parsed(ir);
        let original = minimal_struct("ListGroupClustersRequest");
        let formatted = render_to_formatted_string(&code, &original);
        insta::assert_snapshot!(formatted);
    }

    #[test]
    fn snapshot_delete_group_cluster() {
        let ir = parsed(
            "DeleteGroupClusterRequest",
            "DELETE",
            "2023-02-01",
            "/api/atlas/v2/groups/{group_id}/clusters/{cluster_name}",
            false,
            "()",
        );
        let code = GeneratedCode::from_parsed(ir);
        let original = minimal_struct("DeleteGroupClusterRequest");
        let formatted = render_to_formatted_string(&code, &original);
        insta::assert_snapshot!(formatted);
    }

    #[test]
    fn snapshot_update_group_cluster() {
        let ir = parsed(
            "UpdateGroupClusterRequest",
            "PATCH",
            "2024-10-23",
            "/api/atlas/v2/groups/{group_id}/clusters/{cluster_name}",
            false,
            "ClusterDescription20240805",
        );
        let code = GeneratedCode::from_parsed(ir);
        let original = minimal_struct("UpdateGroupClusterRequest");
        let formatted = render_to_formatted_string(&code, &original);
        insta::assert_snapshot!(formatted);
    }
}
