# 0014 – Bundle package (`vkr.bundle/v0`)

> **Status:** Draft v0. Not a layer and not a conformance target yet. No schema, no vectors in this draft.
> **Date:** 2026-10-15
> **Spec:** Bundle package (cross-cutting; extends [0011-agent-bundle.md](0011-agent-bundle.md))
> **Basis:** [VISION.md](../vision/VISION.md) sections 5 and 7, [0011-agent-bundle.md](0011-agent-bundle.md), [0001-capability.md](0001-capability.md), [0002-grant.md](0002-grant.md), [0003-plan.md](0003-plan.md), `spec/schemas/module-manifest.schema.json`, and [0012-records.md](0012-records.md) (`dcbor` profile). [0013](0013-cbor-plans-ifc.md) (stored plans) is proposed.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174) when they appear in capitals.

0011 defines the agent bundle the Core runs: an Identity, issued Grants, Plans, Modules, and Records, each named by digest. It does not say how an agent is distributed before the owner has issued anything. This spec defines that distributable form, the **bundle package**. A package carries *requests* for authority, never authority. At install, the Core verifies the package, asks the owner, issues grants, and produces the 0011 manifest. The package replaces today's wrapper (prompt + harness + skill markdown + ambient tools).

## 1. Package vs bundle

| | Bundle package (`vkr.bundle/v0`, this spec) | Agent bundle (0011) |
|---|---|---|
| Who signs | Publisher (or owner) | Owner's Core |
| Authority | None. `grant_asks` are templates | Issued capability tokens |
| Plans | `plan_templates` with holes | Verified plans, stored per 0013 |
| Prompts, tone, memory | `prefs` → Records | Records |
| When | Before install | At run time |

**R1.** A package MUST NOT contain a capability token, a pre-granted approval, or an owner signature over a plan. A Core MUST refuse a package that does. *Rationale: invariants 2 and 4. Authority comes from the owner at install, not from the publisher.*

## 2. Body

The body is one document. Canonical bytes are `dcbor` v0.1 (0012 §2). The package digest is SHA-256, unpadded base64url, over the `dcbor` bytes of the body without `sig` (same rule as 0011 R5 and 0012 R7).

| Member | Required | Meaning |
|---|---|---|
| `v` | yes | `"vkr.bundle/v0"`. |
| `id` | yes | `tag:vaikor.com,2026:agent:` plus the capability-id character set (0011 manifest `id`). |
| `name` | yes | Human-facing name. `description` MAY be present. |
| `agent` | yes | `{did, kind: "agent"}`. The publisher-proposed Agent identity. Never the owner, never ambient root. |
| `capabilities` | yes | Array of capability ids the package uses, each with an optional descriptor digest. The publisher MAY include descriptors as hints; they are never authoritative (R7 step 3). |
| `grant_asks` | yes | Array of at least one `{capability, scope, budget, consequential, reason}` (0011 R1 requires one or more Grants). `scope` uses VKR-L2 resource syntax. `reason` is plain language shown on Trusted UI. |
| `plan_templates` | yes | Array of at least one template (0011 R1 requires one or more Plans). Each is an VKR-L3 plan whose `lit` values MAY be holes `{"hole": "<name>"}` filled at run time. |
| `modules` | no | Digests of signed module manifests. |
| `prefs` | no | Array of Record bodies (0012 §3, unsigned) with classes under `adaptation.prefs.*` (0012 requires a registered class root; `adaptation` is the registered root for what the agent learns or is told about the user): tone, language, routing hints, system-prompt text. |
| `personal_model` | no | As in 0011 §4: `{module, adaptation}`. `module` is the digest of a module manifest of kind `model` that MUST also be listed in `modules`. `adaptation` is an array of Record bodies (0012 §3, unsigned). A proposer only, subject to 0011 R8. |
| `sbom` | yes | As in the module manifest. |
| `sig` | yes | The existing signature object, `alg` `EdDSA`, `canon` `dcbor`, signer = publisher `did:key`. |

**R2.** A Core MUST refuse a package with an unknown `v`, with any member not listed in the §2 table (including `views` and `adapters`, which v0 does not define), or with a signature that does not verify over the `dcbor` bytes of the body without `sig`. Unknown members are refused, not ignored. *Rationale: same signing-input rule as tokens, manifests, Records.*

**R3.** Every `plan_templates` step MUST name a capability listed in `capabilities`, and every such capability MUST have a matching `grant_ask`. Holes MUST NOT appear in `capability`, `approval`, `bound`, or `budget`. Only the Core fills holes, at run time, from the owner's input or from Records. A value from a Record keeps that Record's class as its label (0003 R10). It is never an unlabelled `lit`. The filled plan MUST pass the VKR-L3 verifier against the Core catalog. Install consent is not run approval: every consequential step still waits on Trusted UI (invariant 4), and that approval binds to the digest of the filled plan (0013 R2). *Rationale: effects, approval, cost and labels stay static (0003 R3, R6, R7, R10, R13).*

**R4.** `prefs` and any other text MUST be stored as Records and MUST NOT authorize an effect, widen a grant, or satisfy an approval. *Rationale: 0011 R2. Prompts are data.*

**R5.** v0 has no event hooks. A package MUST NOT contain code outside a module, and a module's code runs only as a WASM component (invariant 6). Hooks are listed in §5. *Rationale: a hook would be an effect trigger with no 0011 member to cover it.*

**R6.** A module's required grants, including those of the `personal_model` module, MUST be covered by the package's `grant_asks`. *Rationale: invariant 6, rights at most those of the task.*

## 2a. Mapping to the 0011 manifest

The package does not define a second agent shape. Install (R7) produces exactly the 0011 manifest:

| Package member | 0011 manifest member |
|---|---|
| `id` | `id` (same value) |
| `agent` | `identity` (role Agent) |
| `grant_asks` | `grants`: digests of the tokens the Core issues at install, never the asks |
| `plan_templates` | `plans`: digests of the stored plans (0013) the Core creates from the verified templates |
| `modules` | `modules` (same digests) |
| `prefs`, adaptation Records | `records`: digests of the Records the Core writes (0012) |
| `personal_model.module` | `personal_model` module digest. The same digest is in `modules` and goes through R6 and R7 step 5 like every module |
| `personal_model.adaptation` | `records`: digests of the adaptation Records the Core writes in R7 step 8, plus their digests in the manifest's `personal_model`. The bodies are not copied into the manifest |
| `name`, `description` | not in the manifest. The Core stores them as a `adaptation.prefs.display` Record (data, R4) and shows them at consent |
| `capabilities` | not in the manifest. Used only in R7 steps 3–4; the Core's catalog is authoritative |
| `sbom` | not in the manifest. The Core stores it as a Record of class `documents.sbom` and lists its digest in `records` |
| `sig` (publisher, `dcbor`) | not copied. The manifest gets a new `sig` from the Core, with the canon 0011 R4 requires (`jcs` in v0.1) |

**R2a.** A package MUST NOT carry views. As 0011 R1 says, views are generated per task by VKR-L4 and are not a bundle member. Presentation hints MAY travel as `adaptation.prefs.view.*` Records and are data (R4). Copy for consequential steps always comes from the Core's Trusted UI. *Rationale: one agent shape. A package member with no 0011 counterpart would fork agent = bundle.*

## 3. Install

**R7.** Install MUST follow this order. Any failure MUST refuse the package, and nothing from a later step may become reachable:

1. Signature and publisher trust. The publisher's `did:key` MUST be in the owner's configured publisher set (pinned keys or an owner-approved registry key). Any other publisher is accepted only as `sideloaded` (R9), after an explicit Trusted UI notice. Trust on first use is not allowed.
2. Structure and digests.
3. Capability resolution. Every capability id MUST resolve in the Core's own catalog (owner-installed, signed descriptors). The Core uses its descriptor's `effects`, `data_classes`, `consequential`, and `cost`, never the publisher's. An unknown id refuses the package. If a publisher hint differs from the catalog, the Core uses the catalog and shows the difference at consent.
4. R3 verification of every template against the resolved catalog.
5. Module manifests (R6), including the `personal_model` module.
6. Trusted UI consent. It shows the proposed `agent` DID, every `grant_ask` with its `reason`, budget, and the catalog's `consequential` flag.
7. Audit. The Core appends an entry with the package digest, the consent result, and the digests it is about to create. If the append fails, the install MUST be refused (fail closed).
8. Staging. The Core issues tokens no wider than the asks and the owner's Cedar policy, holder-bound to the `agent` identity (0002 R8). It stores each verified template as a plan (0013), writes `prefs`, `personal_model.adaptation`, `name`/`description`, and `sbom` as Records (0012) with provenance `source` set to the publisher's `did:key` and `derived_from` empty, and assembles the 0011 manifest with the grant, plan, module, and record digests. All of this goes into a staging area that is unreachable: plan execution, grant use, Record reads, and egress MUST NOT see or accept anything staged. A staged token MUST NOT verify at any trust boundary until activation.
9. Validation of the unsigned manifest. The Core runs 0011 §3 steps 2–8 on the staged manifest: digests, identity, grants, plans, modules, records, and approvals.
10. Core signature. Only after step 9 passes does the Core sign the manifest.
11. Full verification. The Core runs the complete 0011 §3, steps 1–9, on the signed manifest, including step 1 (signature and signer).
12. Activation. The Core appends the activation audit entry first. If that append fails, activation MUST be refused. Then it moves the staged objects out of staging in one atomic step.

If any of steps 8–12 fails, the Core MUST first append the refusal to the audit log. If that append fails, the package stays refused and the staged objects stay unreachable. Then it revokes every staged token and removes every staged plan, Record, and manifest. Staged objects never become reachable without step 12.

Every refusal at any step MUST be appended to the audit log with the package digest, or with the SHA-256 of the raw bytes when the package does not decode, and the reason. *Rationale: invariants 2, 3, 4, 9. Publisher authenticity is not catalog truth. Audit comes before effect.*

**R8.** Installing or updating a package MUST NOT widen an existing grant. An update that adds a capability, raises a budget, or turns a step consequential MUST require fresh consent. A `prefs`-only update MAY install without consent only for classes on the owner's non-consequential list (default: `adaptation.prefs.tone`, `adaptation.prefs.language`). Any other `prefs` change, including system-prompt text and routing hints, MUST get at least a Trusted UI notice. An update that changes the `personal_model` module or any adaptation Record MUST get a Trusted UI notice. A changed module also goes through R6 and fresh consent when its grants change. All updates are audited as in R7. *Rationale: attenuation, not expansion.*

**R9.** A package from outside the owner's registries MUST be labelled `sideloaded` by the Core. The publisher MUST NOT set that label. *Rationale: the label is a Core statement.*

## 4. Conversion from wrappers (informative)

| Wrapper artifact | Package target |
|---|---|
| `SKILL.md` name/description | `name`, `description`, one `plan_templates` stub |
| Skill steps ("call tool X") | Plan template steps; unknown tools become capability stubs marked legacy/unattested plus a `grant_ask` |
| Tool allowlist, MCP server | `capabilities` via the MCP binding (VKR-L1) |
| "You may never …" in a system prompt | Dropped as policy; rewritten as Cedar `forbid` rules or an absent `grant_ask`. Tone moves to `prefs` |
| Shell hooks | A module the owner invokes through a plan; event hooks are not in v0 (§5) |
| Memory, `AGENTS.md` | `prefs` Records |

A converter is tooling outside the Core TCB. Its first exit criterion: one skill from a public skill pack converts into a package whose templates pass `vaikor-verify` with no ambient rights and run offline with the stub planner.

## 5. Out of scope

- JSON schema and test vectors (next revision, once 0013 lands).
- Event hooks (`adapters`): a later version may add them, each covered by a plan or module digest in the 0011 manifest. v0 refuses the member (R2).
- Update channel (registry vs mesh) and revocation.
- Whether templates may carry a surface syntax instead of the plan tree.
- The learning loop that writes adaptation Records (0011 §4).
