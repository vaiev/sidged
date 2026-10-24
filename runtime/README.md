# Sidged Runtime (`runtime/`)

The Cargo workspace under `runtime/` implements the Sidged AI Runtime across 12 crates (`sidged-core`, `sidged-capability`, `sidged-grant`, `sidged-verify`, `sidged-mcp`, `sidged-gateway`, `sidged-log`, `sidged-record`, `sidged-model`, `sidged-cli`, `sidged-guard` [binary: `sidged`], and `sidged-tui` [binary: `sidged-tui`]).

## Crate status

| Crate | Status | What is real / limits |
| :--- | :--- | :--- |
| `sidged-core` | implemented | shared Core objects (audit events, record labels); no I/O |
| `sidged-capability` | implemented | capability registry and the JSON Schema subset for inputs and outputs |
| `sidged-grant` | implemented, with limits | token chains, attenuation, expiry, budgets, Cedar evaluation; `authorise` does not check the `data_classes` and `max_amount` caveats, and the holder is the caller-supplied subject |
| `sidged-verify` | implemented | static plan verifier (CEL, bounded `map`), owner-signed stored plans, `CedarFlowPolicy` over catalog-declared data classes |
| `sidged-mcp` | implemented | reads Sidged descriptors from MCP tool metadata; ignores MCP annotations |
| `sidged-gateway` | implemented, with limits | the only HTTP client: residency checks, privacy reports, the local model endpoint; the report's minimisation steps and anonymous account are fixed values, not measured |
| `sidged-log` | implemented | Ed25519-signed SHA-256 hash chain, `sidged log verify` |
| `sidged-record` | implemented | dCBOR records, signatures, retention, the audited offline store |
| `sidged-model` | implemented | the planner interface for `sidged guard` (deterministic stub, OpenAI-compatible provider through the gateway) |
| `sidged-cli` | partial | `sidged run` executor (grants, Cedar, approval, audit before effects), linguist path, intent plans, node executors (no grant check, audit after the run); `swarm.rs` and `webauthn*.rs` are prototypes not wired into a running product path |
| `sidged-guard` | implemented | the `sidged` binary and the `sidged guard` residency scenarios |
| `sidged-tui` | prototype | Demo 1, unsigned preview: one task, one cloud call per human approval |

## Turnkey OS Start (`sidged init` & `sidged task`)

Bootstrap a fresh self-contained workspace and execute a task end-to-end on this node (Companion Linguist `Model -1` -> catalog-verified intent -> the intent's catalog plan (`intent_plan.rs`) -> Static Verifier & `CedarFlowPolicy` -> local executors (`node_exec.rs`) -> Signed Artifact Record + A2UI `ResultSurface`):

```sh
./runtime/target/debug/sidged init --workspace /tmp/sidged-workspace
./runtime/target/debug/sidged task "Write a polite project status email to Alex" \
  --workspace /tmp/sidged-workspace
```

Without a configured Model -1 endpoint `sidged task` refuses (`model-not-configured`). `--hybrid` refuses
(`hybrid-planning-unavailable`): catalog intents are planned on this node, and model-planned intents are roadmap WP 11d.
Consequential steps are denied, because `sidged task` has no Trusted UI channel; capabilities without a backend on this
node refuse.

Every entry point runs through the one engine (`sidged-cli/src/engine.rs`, ROADMAP 11f): `sidged task` and the
companion authorise each step under the node's owner mandate and a per-task token with proof of possession (0002 §6a,
R22-R26), and the reservation and decision are on the audit chain before the effect (0005 R5a). Workspace executors are confined to `<workspace>/files` by one directory handle and `openat2`
(`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, `sidged-cli/src/contained.rs`), not by an OS sandbox.

## Plan Execution (`sidged run`)

`sidged run` requires a capability token and an Ed25519 signing key for effectful execution:

```sh
./runtime/target/debug/sidged run plan.json catalog.json \
  --policy policy.cedar \
  --grant token.json \
  --trusted-issuer did:key:z6Mk... \
  --log-key seed.hex
```

The token is verified (signature, expiry, presence of a holder claim, attenuation, and the trusted root issuer) before any step. Cedar's principal is the token holder, taken from the token's `sub`; the CLI does not authenticate the presenter as that subject, so a local token file works like a bearer token. Grant caveats `data_classes` and `max_amount` are checked when a token is delegated, not at invocation. A missing, expired, widened, or unsigned token is denied and the denial is an audit event. `--now` sets the clock for tests; otherwise the clock is UTC. A set budget is spent before each step.

A consequential step waits for approval on the Unix socket only (`--approve unix:<path> --approve-uid <uid>`, `SO_PEERCRED`, separate approver uid; `0004 R9/R9c`). TTY and `127.0.0.1` HTTP approval are removed and refused. The reply is `approve <who>`, `deny <who>`, or `kill`. No channel, and local mode, means deny. `sidged kill unix:<path>` stops later steps. The audit line records `approve` or `deny`, who, and when. It does not say `allow` for a consequential step.

```sh
./runtime/target/debug/sidged vectors spec/test-vectors
```

That runs the token-chain vectors and the token-check vectors, including every expected refusal.

```sh
./runtime/target/debug/sidged run plan.json catalog.json --policy policy.cedar --grant token.json --trusted-issuer did:key:z6Mk... --log audit.log --log-key seed.hex
./runtime/target/debug/sidged log verify audit.log --public <verifying-key-hex>
```

`--log-key` is a file with 64 hex characters of the Ed25519 seed. Without `--log`, the chain lives at `$XDG_STATE_HOME/sidged/audit.log`, falling back to `~/.local/state/sidged/audit.log`; its resolved path is printed on stderr. A missing key or unwritable chain refuses effects before approval. `sidged run --dry-run` simulates checks without a log or durable spends. Use caps are recovered from signed reservations keyed by issuer, token id, and leaf right index, so keep the same chain across runs. Uses and budgets are checked before each approval; execution remains sequential and a later refusal can follow earlier effects. `sidged log verify` checks the hash chain and the signature. A changed byte fails, and the file stays.

## Records (`0012`)

`sidged record` uses the offline audited store. Every command requires
`--grant token.json --trusted-issuer did:key:... --policy policy.cedar --log-key seed.hex`.
Repeat `--trusted-issuer` for grant precheck issuers only. Record signer anchors
are separate: repeat `--record-anchor <did:key>` for owner-paired Cores; the local
Core key from `--log-key` is always trusted. Guard scenarios use
`config.record_anchors` (an optional array of Core DIDs, default empty), independently
of `config.trusted_issuers`. Store operations still require local Core-issued grants.
`--audience` defaults to `sidged` and is caller-chosen, as for `sidged run`.

```sh
sidged record write record.json --grant token.json --trusted-issuer "$ISSUER" --policy policy.cedar --log-key seed.hex
sidged record read "$DIGEST" --grant token.json --trusted-issuer "$ISSUER" --policy policy.cedar --log-key seed.hex
```

Commands are `write <record.json>`, `read <digest>`, `delete <digest>`,
`retention <digest> <retention.json>`, `import <record.cbor>`, and `expire`.
Write takes the unsigned Record document (an existing signature is replaced by
the Core). Set owner and provenance created/source/plan to null to request
Core values. The CLI step source is the verified grant holder and its plan is null;
conflicting writer claims are refused. Read emits the signed Record as JSON. Write, import, and retention
emit the resulting digest. Retention takes `{ "until": null, "on_expiry": "delete" }`
or a UTC expiry timestamp and returns a new address. Import accepts canonical
dCBOR signed by a configured trusted Core. The grant actions are respectively
`write`, `read`, `delete`, `retain`, and `import` on the class resource
(for example `urn:sidged:record:x-public/weather`). `expire` performs Core R8
maintenance after verifying a live grant presentation for this audience; it
returns the number expired.

`--store <dir>` defaults to `$XDG_STATE_HOME/sidged/records`, falling back to
`~/.local/state/sidged/records`. The resolved absolute store path is printed on
stderr. Its default signed chain is `<store>/audit.log`; `--log <file>` selects
another chain.

## Build and test

From the repository root:

```sh
cargo test --manifest-path runtime/Cargo.toml --workspace --locked
cargo build --manifest-path runtime/Cargo.toml -p sidged-guard -p sidged-tui
```

The default planner is the deterministic stub. CI uses the stub. No API key belongs in this repository.

## Planner environment (`sidged guard` conformance fixtures)

`demo/ch-residency` (`CH` residency fixture) and `demo/public-weather` (`GLOBAL` `unrestricted` residency fixture) are automated conformance and residency fixtures used by the integration test suite (`runtime/sidged-guard/tests/`).

| Variable | Meaning |
|---|---|
| `SIDGED_PROVIDER` | `stub` (default), `local`, or `openai` for any OpenAI-compatible chat API |
| `SIDGED_BASE_URL` | Origin or base path the provider documents. Required when `SIDGED_PROVIDER=openai` |
| `SIDGED_MODEL` | Model id. Defaults to `model` in the scenario `config.json` |
| `SIDGED_API_KEY` | Bearer token. Leave it empty for a local server that does not check one |

`completions_url` appends `/v1/chat/completions` when the base URL has no path. When the base URL already has a path, it appends only `/chat/completions`. HTTP 429 and 503 are retried three times in total, with exponential backoff. Any other status is returned immediately.

Gemini Developer API uses profile **P0** and **GLOBAL** residency; only explicitly `unrestricted` payloads are permitted. Configure the billing project with `SIDGED_GEMINI_PROJECT` (or `provider_project` in `config.json`); missing or blank values refuse before any request. Grounding (`google_search`, `googleSearchRetrieval`, `grounding`), explicit caching (`cachedContent`, `cached_content`), File API inputs/uploads, and Live API/session resumption are unsupported and refused before transport. The reviewed endpoint is `/v1beta/openai/chat/completions`.
