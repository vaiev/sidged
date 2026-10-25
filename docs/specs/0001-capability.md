# 0001 – Capability (VKR-L0 and VKR-L1)

> **Status:** Draft v0.2 (R8 residency fail-closed, 2026-10-15), for implementation of the descriptor and the MCP binding. Grants, plans, and the runtime are later phases.
> **Date:** 2026-10-14
> **Spec:** VKR-L0 Core Objects (the slice this layer needs) and VKR-L1 Capability
> **Basis:** [0000-architektur.md](0000-architektur.md) decisions E1, E2, E3, E4, and E8, accepted 2026-10-14
> **MCP checked:** Model Context Protocol specification, revision 2025-11-25, [Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) and the [schema](https://modelcontextprotocol.io/specification/2025-11-25/schema) `Tool` and `ToolAnnotations` types, read 2026-10-14

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174) when they appear in capitals.

A **capability** is a typed description of one thing a runtime can ask a service, device, module, or legacy app to do. It is not a grant. It does not authorise a call. VKR-L2 will bind a grant to a capability. This document norms the descriptor and one binding: MCP tools.

## 1. L0 slice used here

VKR-L0 names seven primitives: Identity, Capability, Grant, Plan, View, Record, and Module. This document norms Capability. The other six are named so a descriptor can point at them. Their rules are out of scope (section 6).

**R1.** A capability identifier MUST be a URI of the form `tag:vaikor.com,2026:capability:` followed by 1 to 128 characters from ASCII letters, digits, `.`, `_`, and `-`. *Rationale: one spelling for every binding, and the same character set MCP recommends for tool names.*

**R2.** The canonical encoding of a descriptor that this slice checks MUST be JSON. JCS is that encoding when the bytes are signed. Deterministic CBOR (`dcbor`) is the other L0 canonical encoding of the same data model. A v0.1 consumer MAY reject a CBOR descriptor it does not implement. *Rationale: MCP and the v0.1 schemas are JSON, so that is what this slice checks. `dcbor` belongs to VKR-L0, with signatures over an L0 encoding. VKR-L6 specifies the envelope that carries those bytes. It does not define the encoding.*

**R3.** A descriptor MUST use schema version `0.1` until a later minor version is published. A consumer MUST reject a descriptor whose `v` it does not implement. *Rationale: fail closed on an unknown shape.*

## 2. Descriptor

A descriptor is a JSON object with the members in the machine schema [capability-descriptor.schema.json](../../spec/schemas/capability-descriptor.schema.json).

| Member | Required | Meaning |
|---|---|---|
| `v` | yes | Schema version. v0.1 is `"0.1"`. |
| `id` | yes | Capability identifier (R1). |
| `title` | yes | Short human title. |
| `description` | no | What the capability does, for a person and for a model. |
| `input_schema` | yes | JSON Schema 2020-12 object for the arguments. |
| `output_schema` | no | JSON Schema 2020-12 object for a successful result. |
| `effects` | yes | One or more codes from [effects.md](../../spec/registries/effects.md), without duplicates. |
| `data_classes` | yes | Data classes from [data-classes.md](../../spec/registries/data-classes.md). The array MAY be empty when no personal data is involved. |
| `residency` | yes for a capability with the `egress` effect, otherwise no | `{ "tags": [ ... ] }` using [residency.md](../../spec/registries/residency.md). Since v0.2, absent or empty tags fail closed at egress. A publisher that sets no limit MUST say so with the single tag `unrestricted`. |
| `cost` | no | `{ "class": "free" }` or `{ "class": "metered", "max": { "amount", "currency" } }`. |
| `consequential` | yes | Whether a call needs a human approval through Trusted UI before it runs. |

**R4.** `input_schema` MUST be a JSON object. When it has a `type` member, that type MUST be `"object"`. *Rationale: matches MCP, which requires a tool `inputSchema` to be a JSON Schema object and expects object arguments.*

**R5.** When `output_schema` is present, it MUST be a JSON object, and when it has a `type` member, that type MUST be `"object"`. *Rationale: a result the Core can check has a known object shape. MCP allows an optional `outputSchema` on the same terms.*

**R6.** `effects` MUST contain only registered codes, MUST contain at least one code, and MUST NOT repeat a code. *Rationale: the Core computes the effect set before a call. An open string would not be checkable.*

**R7.** Every `data_classes` entry MUST be a registered class, a subclass of one (`contacts.email`), or a private `x-` class. *Rationale: the same vocabulary as egress policy. Private classes fail closed for a consumer that does not know them.*

**R8.** (v0.2, 2026-10-15) Residency tags MUST be `CH`, `EU`, `CH-EU`, `unrestricted`, or an owner tag that starts with `x-`. Several tags combine by intersection. A consumer MUST treat an unrecognised tag as not allowed. At egress, the gateway compares the payload's tags with the destination class from its registry (`CH`, `EU`, or `GLOBAL` for an endpoint with no residency guarantee). An unregistered destination MUST be refused.

- **R8a.** Missing or empty tags MUST be refused for every remote destination (`residency-unsupported`). They no longer mean "no limit".
- **R8b.** `unrestricted` MUST be the only tag on an item (`malformed` otherwise). It allows every registered destination class, including `GLOBAL`.
- **R8c.** `CH`, `EU`, and `CH-EU`, alone or intersected, MUST NOT reach `GLOBAL`. `CH` reaches `CH`, `EU` reaches `EU`, and `CH-EU` reaches both. An empty intersection reaches nothing.
- **R8d.** An `x-` owner tag is allowed only where the owner's mapping (`owner_tags`) names the destination class. Without a mapping it is refused.
- **R8e.** A derived value or Record that combines an `unrestricted` input with a restricted one carries the restricted tags. `unrestricted` is dropped from the union (0012 R10).

*Rationale: before GLOBAL destinations existed, empty tags only reached CH endpoints. With a GLOBAL endpoint, a dropped or forgotten tag would become the widest possible export. Fail-closed plus an explicit declaration makes "no limit" a statement the publisher signs, not a default. Accepted by Grok Bot, 2026-10-15 (Thinker note 2026-10-15-global-residency-lattice). Vectors: `residency/destination.json`. The `residency-regions` set operation is unchanged (`residency.regions.001`: `[]` → `any` is the identity of the intersection, not an egress permission).*

**R9.** A descriptor whose `effects` include `delete`, `execute`, or `egress` MUST set `consequential` to `true`. *Rationale: the publisher must not hide a destructive call, a side effect, or data leaving the device. The Core MAY treat a `false` on a `read` or `write` as consequential anyway. The Core MUST NOT treat a `true` as `false`.*

**R10.** A descriptor whose `effects` include `egress` MUST list at least one data class. *Rationale: the Privacy Gateway cannot report an empty class. What leaves has to be named.*

**R11.** A `metered` cost MUST include `max`. A `free` cost MUST NOT include `max`. `max.amount` MUST be a decimal string. `max.currency` MUST be an ISO 4217 code. *Rationale: the verifier compares an upper bound, not a prose price.*

**R12.** A descriptor describes a capability. It MUST NOT be treated as a grant, a plan, or an approval. *Rationale: E4 separates the primitives. Authority arrives only with a grant (VKR-L2) and, when `consequential` is true, a Trusted UI approval (VKR-L5).*

Effect codes for v0.1:

| Code | Meaning |
|---|---|
| `read` | Observe state. Does not change it and does not send it off the device by itself. |
| `write` | Create or update state. Does not by itself send data off the device. |
| `delete` | Remove or destroy state. Consequential. |
| `execute` | Run a side effect that is not only a read, write, or delete (start a job, send a local command). Consequential. |
| `egress` | Send data off the device. Consequential. Requires data classes. |

## 3. MCP binding

This section is written so it can be filed as an MCP SEP. It is a draft. It is not filed (questions 3 and 10). It was checked against MCP revision 2025-11-25.

MCP tools are model-controlled functions. Each tool has `name`, `description`, `inputSchema`, an optional `outputSchema`, and optional `annotations` (`ToolAnnotations`). The MCP schema states that every property of `ToolAnnotations` is a hint, and that clients MUST NOT make tool-use decisions from annotations that come from an untrusted server. Defaults in that revision: `readOnlyHint` false, `destructiveHint` true when the tool is not read-only, `idempotentHint` false, `openWorldHint` describes an open set of external entities. `Tool` also carries `_meta`, an open object for extensions.

Vaikor does not overload those hints. Hints stay hints.

**R13.** A Vaikor capability descriptor on an MCP tool MUST be carried at `tools[].\_meta["com.vaikor/capability"]` and MUST be a descriptor as in section 2. *Rationale: `_meta` is the extension bag in the 2025-11-25 schema. The key follows the `io.modelcontextprotocol/...` extension style. A SEP MAY later promote the member to a first-class tool field. Until then, this carriage does not require a schema change to MCP itself.*

**R14.** The tool `name` MUST equal the final path segment of the capability `id` after `tag:vaikor.com,2026:capability:`. *Rationale: one call has one name in both protocols. Example: tool `get_current_time` and id `tag:vaikor.com,2026:capability:get_current_time`.*

**R15.** The tool `inputSchema` MUST be the same JSON value as `input_schema`. When the tool has `outputSchema`, it MUST be the same JSON value as `output_schema`. *Rationale: two schemas for one tool will drift. MCP already requires `inputSchema` to be a JSON Schema object.*

**R16.** A Core MUST ignore `ToolAnnotations` when deciding effects, data classes, residency, cost, or whether a call is consequential, whenever `com.vaikor/capability` is present. *Rationale: MCP itself says annotations are hints and are untrusted from an untrusted server. The descriptor is the statement the Core checks. If a hint contradicts the descriptor, the descriptor wins.*

**R17.** A Core MUST NOT authorise a tool call from `ToolAnnotations` alone when `com.vaikor/capability` is absent. It MAY refuse the call, or it MAY show the tool as an unannotated legacy tool that still needs a grant and, if the Core cannot classify it, a Trusted UI approval. *Rationale: E2. Hints are not a capability. `destructiveHint` defaults to true and would both over-block and, if trusted, under-specify data classes.*

**R18.** Servers that attach the descriptor SHOULD set the MCP hints so they do not contradict it: `readOnlyHint` true only when every effect is `read`; `destructiveHint` true when `delete` is present; `openWorldHint` true when `egress` is present. *Rationale: clients that do not understand Vaikor still see a hint. The hint is not the security check.*

Non-normative hint map, for authors migrating a server. It is not an authorisation rule.

| MCP hint | Suggested starting point for a descriptor |
|---|---|
| `readOnlyHint: true` and `openWorldHint: false` | `effects: ["read"]`, `consequential: false` |
| `destructiveHint: true` | include `delete` or `write`, `consequential: true` |
| `openWorldHint: true` | include `egress`, name data classes, `consequential: true` |

A SEP submission would ask the MCP project to register the extension id `com.vaikor/capability`, to document `_meta` carriage, and to state R16 and R17 as client requirements. This repository does not file that SEP in phase 2.

## 4. What a Core does with a descriptor in v0.1

**R19.** Before a call, a Core MUST have a descriptor it has parsed against the v0.1 schema and the semantic rules in section 2. *Rationale: an unparsed tool description is data, invariant 3.*

**R20.** The Core MUST refuse the call when the descriptor fails R6, R7, R8, R9, or R10. *Rationale: fail closed.*

**R21.** The Core MUST still require a grant for every effect (VKR-L2) and a Trusted UI approval when `consequential` is true (VKR-L5). This document does not define the grant or the approval UI. *Rationale: the descriptor says what the call is. It does not say that this caller may make it.*

## 5. Conformance

A conforming descriptor passes [capability-descriptor.schema.json](../../spec/schemas/capability-descriptor.schema.json) and the semantic checks in `spec/validate`. Test vectors live in [spec/test-vectors/capability/descriptor.json](../../spec/test-vectors/capability/descriptor.json). The operation is `capability-check`.

The demo in [docs/demo/mcp-server-time](../demo/mcp-server-time/README.md) annotates the tools of the open-source MCP server `mcp-server-time` (`modelcontextprotocol/servers`, path `src/time`).

## 6. Out of scope

- Grants, attenuation, delegation, budgets on a token, and Cedar policies (VKR-L2).
- The plan language and the verifier's data-flow proof (VKR-L3). v0.1 only gives the verifier a descriptor to read.
- Views, A2UI, and Trusted UI rendering (VKR-L4).
- The core contract beyond R21 (VKR-L5).
- Envelopes and peer-to-peer transport (VKR-L6). Canonical JSON and `dcbor` are L0 encodings. v0.1 conformance for this layer is JSON.
- Privacy reports, provider profiles, and OHTTP (VKR-L7).
- The native image (VKR-L8).
- Filing the MCP SEP, and any MCP feature other than tools (`resources`, `prompts`, `tasks`, MCP Apps).
- Replacing MCP `ToolAnnotations`. They stay hints.
- The hosted crates under `runtime/`. They exist. This spec does not describe them.
