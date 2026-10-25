# Demo: mcp-server-time as Vaikor capabilities

Source: the open-source MCP server `mcp-server-time` in [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers), file `src/time/src/mcp_server_time/server.py`, read on 2026-10-14. The server exposes two tools, `get_current_time` and `convert_time`. Both are annotated in that file with MCP `ToolAnnotations`: `readOnlyHint` true, `destructiveHint` false, `idempotentHint` true, `openWorldHint` false.

Those hints stay hints. [VKR-L1](../../specs/0001-capability.md) carries the Vaikor descriptor at `_meta["com.vaikor/capability"]`. The running server interpolates the host IANA timezone into the tool descriptions. The overlay below keeps the same property names and `required` keys, with a stable description string.

[annotated-tools.json](annotated-tools.json) is the `tools/list` shape a Vaikor-aware client would see. The validator checks each embedded descriptor. It does not start the upstream server and it does not change that repository.

| Tool | Capability id | Effects | Consequential |
|---|---|---|---|
| `get_current_time` | `tag:vaikor.com,2026:capability:get_current_time` | `read` | false |
| `convert_time` | `tag:vaikor.com,2026:capability:convert_time` | `read` | false |

No personal data leaves the device, so `data_classes` is empty and there is no `egress` effect. A grant is still required before a call (VKR-L2). This demo does not issue one.
