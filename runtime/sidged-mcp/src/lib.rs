//! MCP binding from SDG-L1. Descriptors ride at `_meta["io.sidged/capability"]`.
//! Hints in `annotations` are ignored.

use sidged_capability::Registry;

pub fn registry_from_tools(document: &serde_json::Value) -> Result<Registry, String> {
    let tools = document["tools"]
        .as_array()
        .ok_or("tools/list document has no tools array")?;
    let mut descriptors = Vec::new();
    for tool in tools {
        let descriptor = tool
            .get("_meta")
            .and_then(|meta| meta.get("io.sidged/capability"))
            .ok_or_else(|| format!("tool {} has no Sidged descriptor", tool["name"]))?;
        let name = tool["name"].as_str().unwrap_or("");
        let id = descriptor["id"].as_str().unwrap_or("");
        if id.rsplit(':').next() != Some(name) {
            return Err(format!("tool {name} does not match capability id {id}"));
        }
        if tool.get("inputSchema") != Some(&descriptor["input_schema"]) {
            return Err(format!(
                "tool {name} inputSchema does not match input_schema"
            ));
        }
        descriptors.push(descriptor.clone());
    }
    Registry::from_descriptors(&serde_json::Value::Array(descriptors))
}

#[cfg(test)]
mod tests {
    use super::registry_from_tools;

    #[test]
    fn the_time_server_demo_becomes_a_registry() {
        let raw = include_str!("../../../docs/demo/mcp-server-time/annotated-tools.json");
        let document: serde_json::Value = serde_json::from_str(raw).unwrap();
        let registry = registry_from_tools(&document).unwrap();
        assert!(registry
            .get("urn:sidged:capability:get_current_time")
            .is_some());
        assert!(registry.get("urn:sidged:capability:convert_time").is_some());
    }
}
