//! Transforms parsed IR into a `GeneratedCode` model (plain structs, no proc-macro deps).
//! This layer is fully unit-testable.

use crate::parse::ParsedInput;

#[cfg(test)]
use crate::parse::extract_url_param_names;

/// Version variant for the Accept header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionKind {
    Date { year: u16, month: u8, day: u8 },
    Preview,
    Upcoming { year: u16, month: u8, day: u8 },
}

/// A generated struct (e.g. UrlParams or Operation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedStruct {
    pub name: String,
    pub fields: Vec<GeneratedField>,
}

/// A single field in a generated struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedField {
    pub name: String,
    pub ty: String,
    pub is_public: bool,
}

/// The impl block for Operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedOperationImpl {
    pub struct_name: String,
    pub method: String,
    pub url_format_string: String,
    pub url_param_names: Vec<String>,
    pub is_paginated: bool,
    pub response_type: String,
    pub version: VersionKind,
}

/// Full generated output model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedCode {
    pub original_struct_name: String,
    pub url_params_struct: Option<GeneratedStruct>,
    pub operation_struct: GeneratedStruct,
    pub operation_impl: GeneratedOperationImpl,
}

/// Convert a URL template with `{param}` placeholders to a format! string with `{}`.
fn url_template_to_format_string(template: &str) -> String {
    let mut result = String::new();
    let mut chars = template.chars();
    while let Some(c) = chars.next() {
        if c == '{' {
            result.push_str("{}");
            // Skip past the param name and the closing '}' (take_while consumes it when checking)
            let _: String = chars.by_ref().take_while(|&c| c != '}').collect();
        } else {
            result.push(c);
        }
    }
    result
}

fn parse_version(s: &str) -> Option<VersionKind> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("preview") {
        return Some(VersionKind::Preview);
    }
    if let Some(date_part) = s.strip_suffix(".upcoming") {
        return parse_date(date_part).map(|(y, m, d)| VersionKind::Upcoming {
            year: y,
            month: m,
            day: d,
        });
    }
    parse_date(s).map(|(y, m, d)| VersionKind::Date {
        year: y,
        month: m,
        day: d,
    })
}

fn parse_date(s: &str) -> Option<(u16, u8, u8)> {
    let parts: Vec<&str> = s.splitn(3, '-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: u16 = parts[0].parse().ok()?;
    let month: u8 = parts[1].parse().ok()?;
    let day: u8 = parts[2].parse().ok()?;
    Some((year, month, day))
}

/// Base name for generated types: strip "Request" suffix if present.
fn base_name(struct_name: &str) -> &str {
    struct_name
        .strip_suffix("Request")
        .unwrap_or(struct_name)
}

impl GeneratedCode {
    pub fn from_parsed(ir: ParsedInput) -> Self {
        let base = base_name(&ir.struct_name).to_string();
        let operation_name = format!("{}Operation", base);
        let url_params_name = format!("{}OperationUrlParams", base);

        let url_params_struct = if ir.url_param_names.is_empty() {
            None
        } else {
            Some(GeneratedStruct {
                name: url_params_name.clone(),
                fields: ir
                    .url_param_names
                    .iter()
                    .map(|n| GeneratedField {
                        name: n.clone(),
                        ty: "String".to_string(),
                        is_public: true,
                    })
                    .collect(),
            })
        };

        let mut operation_fields = Vec::new();
        if url_params_struct.is_some() {
            operation_fields.push(GeneratedField {
                name: "url_parameters".to_string(),
                ty: url_params_name,
                is_public: true,
            });
        }
        if ir.is_paginated {
            operation_fields.push(GeneratedField {
                name: "pagination".to_string(),
                ty: "PaginationRequest".to_string(),
                is_public: true,
            });
        }
        operation_fields.push(GeneratedField {
            name: "body".to_string(),
            ty: ir.struct_name.clone(),
            is_public: true,
        });

        let url_format_string = url_template_to_format_string(&ir.url_template);
        let version = parse_version(&ir.version_str).unwrap_or(VersionKind::Preview);

        GeneratedCode {
            original_struct_name: ir.struct_name.clone(),
            url_params_struct,
            operation_struct: GeneratedStruct {
                name: operation_name.clone(),
                fields: operation_fields,
            },
            operation_impl: GeneratedOperationImpl {
                struct_name: operation_name,
                method: ir.method,
                url_format_string,
                url_param_names: ir.url_param_names,
                is_paginated: ir.is_paginated,
                response_type: ir.response_type,
                version,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            url_param_names: extract_url_param_names(url_template),
            is_paginated,
            response_type: response_type.to_string(),
        }
    }

    #[test]
    fn strips_request_suffix_for_operation_name() {
        let ir = parsed(
            "ListGroupClusterRequest",
            "GET",
            "2024-08-05",
            "/api/groups/{group_id}/clusters",
            true,
            "ClusterSummary",
        );
        let code = GeneratedCode::from_parsed(ir);
        assert_eq!(code.operation_struct.name, "ListGroupClusterOperation");
    }

    #[test]
    fn keeps_name_without_request_suffix() {
        let ir = parsed(
            "ListClusters",
            "GET",
            "2024-08-05",
            "/api/clusters",
            false,
            "ClusterSummary",
        );
        let code = GeneratedCode::from_parsed(ir);
        assert_eq!(code.operation_struct.name, "ListClustersOperation");
    }

    #[test]
    fn url_params_extracted_from_template() {
        let ir = parsed(
            "ListRequest",
            "GET",
            "2024-08-05",
            "/groups/{group_id}/clusters/{cluster_id}",
            false,
            "T",
        );
        let code = GeneratedCode::from_parsed(ir);
        let params = &code.url_params_struct.unwrap().fields;
        let names: Vec<&str> = params.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["group_id", "cluster_id"]);
    }

    #[test]
    fn no_url_params_struct_when_template_has_no_placeholders() {
        let ir = parsed(
            "ListRequest",
            "GET",
            "2024-08-05",
            "/api/clusters",
            false,
            "T",
        );
        let code = GeneratedCode::from_parsed(ir);
        assert!(code.url_params_struct.is_none());
    }

    #[test]
    fn url_template_to_format_string_empty() {
        assert_eq!(url_template_to_format_string(""), "");
    }

    #[test]
    fn url_template_to_format_string_no_placeholders() {
        assert_eq!(
            url_template_to_format_string("/api/atlas/v2/clusters"),
            "/api/atlas/v2/clusters"
        );
    }

    #[test]
    fn url_template_to_format_string_single_placeholder() {
        assert_eq!(
            url_template_to_format_string("/api/atlas/v2/groups/{group_id}/clusters"),
            "/api/atlas/v2/groups/{}/clusters"
        );
    }

    #[test]
    fn url_template_to_format_string_multiple_placeholders() {
        assert_eq!(
            url_template_to_format_string("/groups/{group_id}/clusters/{cluster_name}"),
            "/groups/{}/clusters/{}"
        );
    }

    #[test]
    fn url_format_string_replaces_placeholders() {
        let ir = parsed(
            "ListRequest",
            "GET",
            "2024-08-05",
            "/api/atlas/v2/groups/{group_id}/clusters",
            true,
            "T",
        );
        let code = GeneratedCode::from_parsed(ir);
        assert_eq!(
            code.operation_impl.url_format_string,
            "/api/atlas/v2/groups/{}/clusters"
        );
    }

    #[test]
    fn paginated_adds_pagination_field() {
        let ir = parsed("ListRequest", "GET", "2024-08-05", "/api/foo", true, "Item");
        let code = GeneratedCode::from_parsed(ir);
        let has_pagination = code
            .operation_struct
            .fields
            .iter()
            .any(|f| f.name == "pagination");
        assert!(has_pagination);
    }

    #[test]
    fn non_paginated_no_pagination_field() {
        let ir = parsed("GetRequest", "GET", "2024-08-05", "/api/foo", false, "Item");
        let code = GeneratedCode::from_parsed(ir);
        let has_pagination = code
            .operation_struct
            .fields
            .iter()
            .any(|f| f.name == "pagination");
        assert!(!has_pagination);
    }

    #[test]
    fn version_date_parsed() {
        let ir = parsed("R", "GET", "2024-08-05", "/x", false, "T");
        let code = GeneratedCode::from_parsed(ir);
        assert!(matches!(
            code.operation_impl.version,
            VersionKind::Date {
                year: 2024,
                month: 8,
                day: 5
            }
        ));
    }

    #[test]
    fn version_preview_parsed() {
        let ir = parsed("R", "GET", "preview", "/x", false, "T");
        let code = GeneratedCode::from_parsed(ir);
        assert!(matches!(code.operation_impl.version, VersionKind::Preview));
    }
}
