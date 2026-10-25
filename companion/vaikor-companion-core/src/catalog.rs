// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! The `@vaiev/ui` v4 primitive catalog (`ui/a2ui-catalog.v4.json`) and surface validation.
//!
//! A primitive is chosen for data by its `binds` in catalog order: the first primitive
//! whose `shape` pattern matches the data's JSON Schema (or whose `mime_prefix` matches an
//! artifact type) renders it. Every surface is validated against the primitives' own
//! `props_schema` before it reaches a webview.

use serde::Deserialize;
use serde_json::Value;

use crate::schema;

pub const A2UI_CATALOG_JSON: &str = include_str!("../../../ui/a2ui-catalog.v4.json");
pub const SURFACE_VERSION: &str = "4.0";
pub const SURFACE_KINDS: [&str; 3] = ["input", "output", "clarification"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRange {
    pub min: usize,
    pub max: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bind {
    #[serde(default)]
    pub shape: Option<Value>,
    #[serde(default)]
    pub mime_prefix: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Primitive {
    pub name: String,
    pub role: String,
    pub description: String,
    pub children: ChildRange,
    pub binds: Vec<Bind>,
    pub tokens: Vec<String>,
    pub props_schema: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_text: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2uiCatalog {
    pub v: String,
    pub about: String,
    pub token_source: String,
    pub limits: Limits,
    pub primitives: Vec<Primitive>,
}

/// True when the data schema has at least the structure the bind pattern names.
pub fn shape_matches(pattern: &Value, data_schema: &Value) -> bool {
    let (Some(pattern), Some(data)) = (pattern.as_object(), data_schema.as_object()) else {
        return false;
    };
    pattern.iter().all(|(key, want)| match key.as_str() {
        "type" => match data.get("type") {
            Some(Value::String(t)) => Some(t.as_str()) == want.as_str(),
            Some(Value::Array(ts)) => ts.contains(want),
            _ => false,
        },
        "items" => data.get("items").is_some_and(|i| shape_matches(want, i)),
        "required" => {
            let have = data.get("required").and_then(Value::as_array);
            want.as_array()
                .into_iter()
                .flatten()
                .all(|name| have.is_some_and(|have| have.contains(name)))
        }
        _ => false,
    })
}

impl A2uiCatalog {
    pub fn builtin() -> Result<Self, String> {
        Self::parse(A2UI_CATALOG_JSON)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let catalog: Self =
            serde_json::from_str(text).map_err(|e| format!("a2ui-catalog-invalid: {e}"))?;
        if catalog.v != SURFACE_VERSION {
            return Err(format!("a2ui-catalog-invalid: version {}", catalog.v));
        }
        let mut names = std::collections::BTreeSet::new();
        for primitive in &catalog.primitives {
            if !names.insert(primitive.name.as_str()) {
                return Err(format!(
                    "a2ui-catalog-invalid: duplicate {}",
                    primitive.name
                ));
            }
            let unsupported = schema::unsupported_keywords(&primitive.props_schema);
            if !unsupported.is_empty() {
                return Err(format!(
                    "a2ui-catalog-invalid: {} uses unenforced keywords {unsupported:?}",
                    primitive.name
                ));
            }
            if primitive.children.min > primitive.children.max {
                return Err(format!(
                    "a2ui-catalog-invalid: {} children range",
                    primitive.name
                ));
            }
        }
        Ok(catalog)
    }

    pub fn primitive(&self, name: &str) -> Option<&Primitive> {
        self.primitives.iter().find(|p| p.name == name)
    }

    /// The first primitive (catalog order) that binds this data schema.
    pub fn bind_schema(&self, data_schema: &Value) -> Option<&Primitive> {
        self.primitives.iter().find(|p| {
            p.binds.iter().any(|b| {
                b.shape
                    .as_ref()
                    .is_some_and(|s| shape_matches(s, data_schema))
            })
        })
    }

    /// The first primitive (catalog order) that binds this artifact media type.
    pub fn bind_mime(&self, mime: &str) -> Option<&Primitive> {
        self.primitives.iter().find(|p| {
            p.binds
                .iter()
                .any(|b| b.mime_prefix.as_ref().is_some_and(|m| mime.starts_with(m)))
        })
    }

    /// The first primitive with this role, for structure the composer always needs.
    pub fn by_role(&self, role: &str) -> Result<&Primitive, String> {
        self.primitives
            .iter()
            .find(|p| p.role == role)
            .ok_or_else(|| format!("a2ui catalog has no {role} primitive"))
    }

    /// Validate a surface document; empty means it may be rendered.
    pub fn validate_surface(&self, surface: &Value) -> Vec<String> {
        let mut problems = Vec::new();
        let Some(object) = surface.as_object() else {
            return vec!["surface is not an object".into()];
        };
        for key in object.keys() {
            if !["v", "kind", "source", "nodes"].contains(&key.as_str()) {
                problems.push(format!("unexpected surface member {key}"));
            }
        }
        if object.get("v").and_then(Value::as_str) != Some(SURFACE_VERSION) {
            problems.push(format!("surface v must be {SURFACE_VERSION}"));
        }
        if !object
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|k| SURFACE_KINDS.contains(&k))
        {
            problems.push("surface kind must be input, output or clarification".into());
        }
        if !object.get("source").is_some_and(Value::is_object) {
            problems.push("surface source must be an object".into());
        }
        let Some(nodes) = object.get("nodes").and_then(Value::as_array) else {
            problems.push("surface nodes must be an array".into());
            return problems;
        };
        let mut count = 0;
        for (index, node) in nodes.iter().enumerate() {
            self.check_node(
                node,
                &format!("nodes/{index}"),
                1,
                &mut count,
                &mut problems,
            );
        }
        if count > self.limits.max_nodes {
            problems.push(format!("more than {} nodes", self.limits.max_nodes));
        }
        problems
    }

    fn check_node(
        &self,
        node: &Value,
        path: &str,
        depth: usize,
        count: &mut usize,
        problems: &mut Vec<String>,
    ) {
        *count += 1;
        if depth > self.limits.max_depth {
            problems.push(format!("{path}: deeper than {}", self.limits.max_depth));
            return;
        }
        let Some(object) = node.as_object() else {
            problems.push(format!("{path}: node is not an object"));
            return;
        };
        for key in object.keys() {
            if !["primitive", "props", "children"].contains(&key.as_str()) {
                problems.push(format!("{path}: unexpected node member {key}"));
            }
        }
        let name = object
            .get("primitive")
            .and_then(Value::as_str)
            .unwrap_or("");
        let Some(primitive) = self.primitive(name) else {
            problems.push(format!("{path}: unknown primitive {name:?}"));
            return;
        };
        let props = object.get("props").cloned().unwrap_or(Value::Null);
        for problem in schema::validate(&primitive.props_schema, &props) {
            problems.push(format!("{path}/props{problem}"));
        }
        let children = match object.get("children") {
            None => Vec::new(),
            Some(Value::Array(children)) => children.clone(),
            Some(_) => {
                problems.push(format!("{path}: children must be an array"));
                return;
            }
        };
        if children.len() < primitive.children.min || children.len() > primitive.children.max {
            problems.push(format!(
                "{path}: {name} takes {}..{} children",
                primitive.children.min, primitive.children.max
            ));
        }
        for (index, child) in children.iter().enumerate() {
            self.check_node(
                child,
                &format!("{path}/children/{index}"),
                depth + 1,
                count,
                problems,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn builtin_catalog_parses_and_uses_only_real_tokens() {
        let catalog = A2uiCatalog::builtin().unwrap();
        let names: Vec<&str> = catalog.primitives.iter().map(|p| p.name.as_str()).collect();
        for expected in [
            "IntentHeader",
            "FlowBadge",
            "ArtifactCard",
            "StepTimeline",
            "SplitPane",
            "DataTable",
            "FormSurface",
        ] {
            assert!(names.contains(&expected), "{expected}");
        }
        // Every token a primitive names is defined by the vendored @vaiev/ui v4 tokens or the Vaikor theme.
        let defined = [
            include_str!("../../../ui/vaiev-ui/tokens/tokens.css"),
            include_str!("../../../ui/vaiev-ui/vaikor-theme.css"),
        ];
        assert!(catalog.token_source.ends_with("tokens.css"));
        for primitive in &catalog.primitives {
            for token in &primitive.tokens {
                let definition = format!("{token}:");
                assert!(
                    defined.iter().any(|css| css.contains(&definition)),
                    "{} uses undefined token {token}",
                    primitive.name
                );
            }
        }
    }

    #[test]
    fn binds_follow_catalog_order_from_specific_to_general() {
        let catalog = A2uiCatalog::builtin().unwrap();
        let steps = json!({"type": "array", "items": {"type": "object",
            "required": ["step_id", "label", "status"]}});
        let rows = json!({"type": "array", "items": {"type": "object"}});
        let object = json!({"type": "object", "properties": {}});
        assert_eq!(catalog.bind_schema(&steps).unwrap().name, "StepTimeline");
        assert_eq!(catalog.bind_schema(&rows).unwrap().name, "DataTable");
        assert_eq!(catalog.bind_schema(&object).unwrap().name, "FormSurface");
        assert!(catalog.bind_schema(&json!({"type": "string"})).is_none());
        assert_eq!(
            catalog
                .bind_mime("application/vnd.vaikor.artifact.code+json")
                .unwrap()
                .name,
            "ArtifactCard"
        );
    }

    #[test]
    fn surfaces_are_checked_against_props_schemas_and_limits() {
        let catalog = A2uiCatalog::builtin().unwrap();
        let good = json!({"v": "4.0", "kind": "output", "source": {}, "nodes": [
            {"primitive": "SplitPane", "props": {"orientation": "horizontal"}, "children": [
                {"primitive": "IntentHeader", "props": {"title": "T", "status": "ready"}},
                {"primitive": "StepTimeline", "props": {"steps": []}}
            ]}
        ]});
        assert_eq!(catalog.validate_surface(&good), Vec::<String>::new());
        let bad = json!({"v": "4.0", "kind": "output", "source": {}, "nodes": [
            {"primitive": "SplitPane", "props": {"orientation": "diagonal"}, "children": []},
            {"primitive": "HtmlBlob", "props": {"html": "<script>"}},
            {"primitive": "IntentHeader", "props": {"title": "T", "status": "ready", "onclick": "x"}}
        ]});
        let problems = catalog.validate_surface(&bad);
        assert!(problems
            .iter()
            .any(|p| p.contains("not one of the allowed values")));
        assert!(problems.iter().any(|p| p.contains("takes 2..2 children")));
        assert!(problems.iter().any(|p| p.contains("unknown primitive")));
        assert!(problems
            .iter()
            .any(|p| p.contains("unexpected member onclick")));
    }
}
