# Vaikor — Personal Edge Intelligence OS

[![License: Apache 2.0](https://img.shields.io/badge/Code-Apache_2.0-blue.svg)](LICENSE-CODE)
[![License: CC BY 4.0](https://img.shields.io/badge/Specs-CC_BY_4.0-lightgrey.svg)](LICENSE)

**Vaikor** (<https://vaikor.com>, formerly Sidged) is an open, security-first **Personal Edge Intelligence Operating System and Runtime**.

Instead of wrapping a prompt around an LLM with ambient authority or shipping a classic desktop/app userland, Vaikor structures the system into three strict layers:

```text
+-----------------------------------------------------------------------+
| 3. Generative AI Surface (VKR-L4)                                     |
|    - Declarative A2UI Views & Atomic UI Primitives (@vaiev/ui v4)     |
|    - Core-Owned Trusted UI (SO_PEERCRED Unix Socket Approval & Kill)  |
+-----------------------------------------------------------------------+
| 2. Vaikor AI Runtime (VKR-L0..L7)                                     |
|    - Rust Security Core (Plan Verifier, Grants, Cedar IFC, Gateway)   |
|    - On-Device Model Ensemble (Model -1 Linguist, Model 0, Model 1)   |
|    - Owner Swarm (Edges 1..n, specified) & Signed Records (dCBOR)     |
+-----------------------------------------------------------------------+
| 1. Linux Kernel (VKR-L8 / Host / VM / OCI)                            |
|    - Drivers, Scheduler, Namespace & Process Isolation                |
+-----------------------------------------------------------------------+
```

- **Website & Schemas:** <https://vaikor.com> (`https://vaikor.com/spec/schemas/`)
- **Namespace:** `tag:vaikor.com,2026:`
- **Prefix & Media Types:** `vkr.*` / `application/vnd.vaikor.*`

---

## Status: v0.3 in progress (pre-alpha research preview)

The specifications are drafts and nothing here has had an external security review. What runs today, with tests:

- **Core:** static plan verifier, Ed25519 capability-token chains with attenuation, Cedar policy and information-flow
  control, the Privacy Gateway's residency checks, signed records, and a signed, hash-chained (tamper-evident) audit log.
- **Model -1 on the node:** an utterance in English, German or Swiss German becomes a catalog intent the Core verifies
  (Qwen3-0.6B LoRA, about 1 to 1.5 s per utterance on a laptop CPU, local Unix socket, no network). Verbatim slots must
  occur in the utterance; times and durations are resolved by the Core, not the model.
- **One node executes catalog plans:** reminders, timers, notes and workspace files run for real; consequential steps
  are denied without a Trusted UI; capabilities without a backend on the node refuse. The record holds what happened.
- **Companion:** one Tauri v2 app for Linux desktop and Android (onboarding, intent canvas, Model -1 through a bundled
  llama-server), and an import-free WASM verifier for the browser.

Not yet: Trusted UI approval in the apps and hardware-bound keys (v0.4), device pairing with passkey or swiyu
credential verification and relays (v0.5), message transport, calendar and device-control backends, the Model 1
planner for compositions, signed model and module distribution. See [docs/ROADMAP.md](docs/ROADMAP.md).

### Implementation status

*Implemented*: in the code and tested on the stated path. *Partial*: implemented on some paths or with a stated
limit. *Prototype*: code and tests exist, not wired into a running product path. *Specified*: specification only.

| Area | Status | Where / limits |
| :--- | :--- | :--- |
| Plan verifier (VKR-L3, CEL, bounded `map`) | implemented | `vaikor-verify`; runs before any step on every execution path; one plan parser (`vaikor_verify::stored`) is shared by the verifier, the flow check and the one execution engine (`vaikor-cli/src/engine.rs`) and refuses members the plan schema does not allow, and a step reference passes exactly the referenced output or its declared member (0003 R4a) |
| Information flow control | partial | `CedarFlowPolicy` (`vaikor-verify/src/flow.rs`) on the `vaikor task` and companion path; `vaikor run` and `vaikor guard` use the verifier's stricter built-in rule (no sensitive class reaches egress). Labels are the data classes the capability catalog declares, propagated along step references, not labels of the data actually read; `secrets.*` never reaches egress |
| Capability tokens and Cedar grant policy | partial | one execution engine (`vaikor-cli/src/engine.rs`, 0002 R26) for `vaikor run`, `vaikor guard`, `vaikor task` and the companion accepts the grant before the first step and authorises and reserves every step; `vaikor run` and `vaikor guard` present a token with the holder's proof of possession (R25), `vaikor task` and the companion a one-hour task token the node's executor key mints and proves possession of, accepted only inside the owner mandate that `vaikor init` signs for 30 days (`mandate.json`, `grant.cedar`, renewal by `vaikor mandate renew`; R23-R25); `vaikor-tui`, the record store and swarm workers check grants on their own paths |
| Grant caveats `data_classes`, `max_amount` | partial | enforced at delegation and at use (0002 R22) wherever grants are checked (`vaikor run`, `vaikor guard`, `vaikor task`, the companion); the node path reserves uses and the mandate's period budget on the audit chain before each effect (R20, R21, R24); the record store refuses amount caps |
| Holder binding | partial | the token must carry `cnf`; on every engine entry point the presenter signs over the plan digest and a nonce the Core draws for the run (0002 R25; `vaikor run --holder-key`), and only the proven holder is authorised; a dry run without a holder key is checked unproven and has no effect. `vaikor-tui` and the record store still take the holder from the token |
| Trusted UI approval | partial | Unix socket with `SO_PEERCRED` and R9c checks in `vaikor run`, `vaikor guard`, `vaikor-tui`; `vaikor task` and the apps deny consequential steps; WebAuthn approval is Core-side only ([WP 16](docs/ROADMAP.md)) |
| Privacy Gateway | implemented | `vaikor-gateway` is the only HTTP client; residency checks fail closed; minimisation fields in the report are fixed values, see invariant 5 |
| Audit log (signed hash chain) | partial | every execution path appends each decision before its effect and the outcome after (0005 R5a); a failing append stops the plan; an effectful run without a signed chain refuses before its first step (a dry run may omit it); the swarm prototype marks a worker revoked before it appends the audit entry |
| Records (dCBOR, signed) | implemented | `vaikor-record`, `vaikor record`; signed result records of `vaikor task` |
| Local mode (`VAIKOR_LOCAL=1`) | partial | gateway egress, the approval channel and the swarm mesh refuse; no kernel-level filter; see invariant 7 for the model connection |
| Workspace containment | partial | `<workspace>/files` is opened once as a directory handle (refused when it is a symlink or not owned by the Core uid) and every workspace file operation resolves beneath it with Linux `openat2(RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS)` (`vaikor-cli/src/contained.rs`), so a symlink or rename raced into the tree cannot lead outside; files with more than one hard link are refused; timers and reminders change under a lock with atomic replace, task records go through the record store; no OS sandbox |
| Model -1 linguist | implemented | `vaikor task`, companion desktop and Android; the deployed weights emit the full v0.1 envelope. The compact v0.2 proposal with catalog-constrained decoding (0017 L3a, L8) is in the Core and selected by `model.output`, and no deployed weights use it yet |
| Model 0, Model 1 | prototype | training code in `local-training/`; not on the runtime path ([WP 11d](docs/ROADMAP.md)) |
| Hybrid cloud planning | specified | 0009; `vaikor task --hybrid` refuses |
| Swarm (0015) | prototype | enrollment, handshake, envelopes, drift revocation as library functions with tests, behind the `vaikor-cli` feature `experimental` (off by default, with the signed-adapter prototype and `vaikor swarm measure`) until v0.5 rebuilds them on the one engine; no multi-device run ([WP 19 to 21](docs/ROADMAP.md)) |
| Pairing (0016) | prototype | signed QR invites and `did:key` presentations; passkey and `swiyu` verification and transports are not implemented ([WP 19, 20](docs/ROADMAP.md)) |
| Modules (WASI components) | specified | no WebAssembly component engine in the workspace; adapters are Rust code in the Core |
| Signed model and module packages | specified | [WP 25](docs/ROADMAP.md) |

---

## Core Architecture & The 7 Primitives (`VKR-L0`)

Vaikor replaces traditional OS userland concepts (user accounts, unvetted binaries, ambient file permissions, and monolithic apps) with seven building blocks. The table states the design; the status table above says which parts run today.

| Primitive | Replaces | Vaikor Mechanism |
| :--- | :--- | :--- |
| **Identity** | User accounts & ambient UIDs | Ed25519 `did:key` device/owner identities; the pairing prototype verifies the `did:key` signature of a presentation; WebAuthn assertions are verified Core-side for approvals; passkey and `swiyu` SD-JWT VC pairing are specified (WP 19) |
| **Capability** | Apps, syscalls, raw IPC | Typed descriptor (`tag:vaikor.com,2026:capability:*`) declaring input/output schemas, effects, data classes, residency tags, cost, and `consequential` flags |
| **Grant** | Ambient file/app permissions | Attenuable Ed25519 capability token chains (`vkr-cap`) with a holder claim (`cnf.jkt`/`cnf.kid`), budgets, max-use caps, expiry, and **Cedar** policy evaluation; checked by `vaikor run`, not yet by `vaikor task` |
| **Plan** | Arbitrary scripts & agent loops | Declarative DAG (`VKR-L3`) with bounded `map` (`1..32`), **CEL** expressions, static verification before any step, and **Cedar Information Flow Control (IFC)** over catalog-declared data classes |
| **View** | Static app windows | Intent-generated declarative **A2UI** surfaces (`ResultSurface`, `IntentHeader`, `FlowBadge`, `ArtifactCard`, `StepTimeline`) + a **Core-owned Trusted UI** for approvals (today the `SO_PEERCRED` Unix socket; not yet in the apps) |
| **Record** | Unstructured files & databases | Content-addressed, Ed25519-signed **dCBOR** / JCS objects carrying data class, provenance (`derived_from`, `plan`), residency tag, and retention policy |
| **Module** | Unverified packages & plugins | Capability-gated adapters (`VaikorAdapter`, Rust code in the Core today); isolated **WASI 0.3** WebAssembly components are specified, no component engine exists yet |

---

## The 9 Security Invariants & ISO/IEC 27090 Alignment

Nine invariants are the design rules for every layer and deployment target (Bare Metal, VM, Host Service, OCI Container, and Swarm Worker); spec 0016 maps them to **ISO/IEC 27090** (*AI Cybersecurity*), without an external assessment yet. Where the code does not yet enforce a rule on every path, the rule says so.

1. **The Model Is Never the Security Boundary:** Models (`Model -1`, `Model 0`, `Model 1`, or cloud planners) only *propose* intents, views, or plans. The deterministic Rust Core (`vaikor-verify`, `vaikor-grant`, `vaikor-gateway`) decides.
2. **No Effect Without a Valid Grant:** Every capability call requires a cryptographically verified, non-expired capability token for its holder and a `Permit` decision from the owner's Cedar policy. *Status:* enforced by `vaikor run` and `vaikor guard`, and by `vaikor task` and the companion under a task token inside the owner's mandate (0002 §6a); without a valid mandate the node runs no step. Grant caveats `data_classes` and `max_amount` are checked at use where grants are checked (0002 R22). All four entry points run through one engine (R26), and every presenter proves possession of the token key over the plan digest and a fresh Core nonce before any step (R25; `vaikor run --holder-key`).
3. **All External Inputs Are Untrusted Data Until Verified:** Plans are statically verified before any field (including residency) is read. `CedarFlowPolicy` (`runtime/vaikor-verify/src/flow.rs`) checks the declared flows of a plan and unconditionally blocks `secrets.*` from reaching any egress capability. *Status:* labels come from the data classes the capability catalog declares, not from the data actually read, so IFC limits what a plan may route, not what a poisoned input contains.
4. **Consequential Steps Require Human Approval via Trusted UI:** Consequential actions block on the Core-owned Unix domain socket (`--approve unix:<path> --approve-uid <uid>`), verified server-side via Linux `SO_PEERCRED` with UID/GID/sudoers/doas separation checks (`0004 R9/R9c`). Without a channel (`vaikor task`, the apps, local mode) consequential steps are denied. *Status:* the one execution engine asks for approval and checks the kill switch before every step on every entry point; a step the plan or the catalog marks consequential is never decided `allow`.
5. **Gateway-Only Egress with Privacy Reports:** Every outbound network call passes through `vaikor-gateway`, enforcing fail-closed residency checks (`CH`, `EU`, `CH-EU`, `unrestricted`) and emitting a Privacy Report, appended to the signed audit chain, that binds the SHA-256 digest of the payload (or of the URL for a GET). *Status:* the report states the minimisation steps `redaction` and `no-persistent-id` and an anonymous, unlinkable account for every call; the gateway does not redact yet, and a call with a provider credential is linkable to that account.
6. **Sandboxed Execution:** Capabilities execute with at most the attenuated rights of the task that invoked them. *Status:* not implemented as a sandbox. Executors run in the Core process; workspace capabilities are confined to `<workspace>/files` by a directory handle and `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` on every open, which the kernel enforces at the moment of use; nothing else in the Core process is confined. Rights are attenuated only where grants are checked (invariant 2).
7. **Full Offline Capability & Local-Mode Latch (`VAIKOR_LOCAL=1`):** Local mode refuses internet egress in the gateway, the approval channel of `vaikor run` and `vaikor guard`, and the swarm mesh (no bind, listen or connect); this is enforced in those code paths, not by a kernel filter. *Status:* each `LocalModel` client makes at most one model connect, but the linguist and the local generator create a new client per call, so a task can make several connects. The default endpoint is an AF_UNIX socket with an `SO_PEERCRED` uid check; an explicitly configured `tcp:127.0.0.1:<port>` endpoint is allowed in local mode without a peer check (`vaikor guard` audits its risk note).
8. **Minimal Auditable Core:** The Rust Core (`runtime/`) is kept compact and dependency-minimal; adapters and tools attach at verified trust boundaries.
9. **Cryptographic Hash-Chained Audit Log:** Every approval, denial, grant spend, privacy report, record write, and swarm event is appended to an Ed25519-signed SHA-256 hash chain (`vaikor log verify`). *Status:* every execution path appends a step's decision before its effect and its outcome after, and a failing append stops the plan (0005 R5a; failure-injection tests for locked, corrupt and unwritable logs). An effectful run without a signed audit chain refuses before its first step; only a dry run may omit it.

---

## On-Device Model Ensemble & Hybrid Planning

Vaikor uses small models (`local-training/`) on consumer hardware. They only propose; the Core decides.

- **`Model -1` (Companion Linguist, deployed):** turns an English, German or Swiss German utterance into a linguist envelope (language, catalog intent, slots); the Core keeps only those and re-derives the rest from the intent catalog (`runtime/vaikor-cli/src/linguist.rs`, spec 0017). Missing slots become a local clarification question.
- **`Model 0` (Intent Router & A2UI Composer, experimental):** demonstration trainer on a few templates (`local-training/experimental/train_edge_llm.py`); not on the runtime path.
- **`Model 1` (Planner, experimental):** demonstration trainer (`local-training/experimental/train_planner_think.py`, five repeated templates) for VKR-L3 plans with a verifier-guided repair round. Today every intent's plan comes from the catalog (0017 §2b); model-planned compositions are WP 11d.
- **Hybrid cloud planning:** specified (0009), not implemented; `vaikor task --hybrid` refuses.

---

## Swarm Mode (`Spec 0015` & `Spec 0016`)

Specified in 0015 and 0016. The runtime implements enrollment, signed envelopes, drift revocation and the pairing
protocol as library functions (`runtime/vaikor-cli/src/swarm.rs`) exercised by tests; a new node enrolls no edges,
and running across several devices arrives with WP 19 to 21. In the specification, the Vaikor runtimes of one owner cooperate as a **Swarm** (`Edge 1` Control Core + `Edges 2..n` Worker Cores):

- **Enrollment & Attenuated Delegation (`S1–S5`):** Edge 1 requires owner approval, compares the image digest the edge declares with its own, rejects RFC 8032 test keys and duplicate DIDs, and issues an attenuated Ed25519 capability grant bound to the worker's `did:key`. The digest is declared, not measured: nothing in the runtime hashes a running image yet.
- **Mutual `did:key` Handshake & Envelope Verification (`S6–S10`):** Control and Worker perform a challenge-response handshake (`vkr.handshake/v0\0`) before exchanging signed `SwarmEnvelope` messages. Workers independently verify grants and Cedar policies, refuse consequential steps (`S9`), and log pre-effect audit records.
- **Worker Revocation & Replacement:** If a worker returns a malformed proposal, one that fails the catalog-digest or `CedarFlowPolicy` check (the full `VKR-L3` verifier is not called on proposals yet), or reports a measurement that drifts (`S11`), Edge 1 marks the worker revoked in its swarm state, then audits it (`swarm_worker_culled` / `swarm_drift_revoked`), and enrolls a replacement `did:key` supplied by the caller (with owner approval). The runtime does not stop or start any process; that is left to the operator.
- **Companion Pairing (`Spec 0016`):** short-lived signed QR invites (`vkr://pair/v0`) and `did:key`-signed device presentations are implemented; verifying passkey assertions and Swiss E-ID `swiyu` SD-JWT VC credentials, and the `local-direct` / `cloud-to-local-e2ee` / `local-to-web-to-local-e2ee` transports, are not yet (WP 19, 20).

---

## Quickstart & CLI Usage

### 1. Build & Verify the Workspace

```sh
cargo test --manifest-path runtime/Cargo.toml --workspace --locked
cargo build --manifest-path runtime/Cargo.toml --release -p vaikor-guard -p vaikor-tui
```

The compiled binaries are `./runtime/target/release/vaikor` and `./runtime/target/release/vaikor-tui`.

### 2. Turnkey 1-Command Workspace Init & Task Execution

Bootstrap a fresh self-contained workspace (keys, default Cedar policy, capability catalog, and signed root grant) and execute a natural-language task end-to-end:

```sh
# 1. Initialize workspace (0600 Ed25519 keys, the default-flow policy.cedar, catalog.json, manifest.json, audit log)
./runtime/target/release/vaikor init --workspace /tmp/my-vaikor-os

# 2. Serve Model -1 (the companion linguist) on a private AF_UNIX socket for this workspace
bash scripts/serve-local-linguist.sh <vaikor-linguist-q8_0.gguf> --workspace /tmp/my-vaikor-os &

# 3. Run a task: Model -1 -> catalog-verified intent -> catalog plan -> verifier + Cedar flow policy -> local executors -> signed record
./runtime/target/release/vaikor task "Schreib Anna wegen dem Meeting morgen" \
  --workspace /tmp/my-vaikor-os
```

Without a configured model `vaikor task` refuses (`model-not-configured`); there is no keyword fallback. An utterance
that misses a required slot returns the local clarification question and starts nothing.

`vaikor task` outputs a JSON bundle containing:
- the outcome of every plan step (completed, denied, refused, skipped) with the executor's output,
- the signed **record** (`application/vnd.vaikor.artifact.solution+json`) and the declarative **A2UI `ResultSurface`**
  (`IntentHeader`, `FlowBadge`, `ArtifactCard`, `StepTimeline`) written to the workspace.

The task runs the intent's catalog plan on this node: local capabilities execute, capabilities without a backend on
this node refuse, and consequential steps are denied because `vaikor task` has no Trusted UI channel. The signed
record holds exactly the step outcomes. `vaikor task` does not check a capability token yet, and it appends the step
outcomes to the audit chain after the plan has run (invariants 2 and 9). `--hybrid` refuses until model-planned
intents exist (roadmap WP 11d).

### 3. Plan Execution, Record Store & Audit Verification

```sh
# Generate fresh Ed25519 issuer and holder keys
./runtime/target/release/vaikor keygen /tmp/vaikor-keys

# Execute a verified plan with capability token, Cedar policy, and signed audit log
./runtime/target/release/vaikor run plan.json catalog.json \
  --policy policy.cedar \
  --grant token.json \
  --trusted-issuer did:key:z6Mk... \
  --log /tmp/audit.log \
  --log-key /tmp/vaikor-keys/issuer.key

# Verify the cryptographic SHA-256 hash chain and Ed25519 signatures of the audit log
./runtime/target/release/vaikor log verify /tmp/audit.log --public <verifying-key-hex>
```

### 4. Offline UI Shell

Open the zero-network static A2UI shell (`ui/shell/`, enforcing `connect-src 'none'` and safe DOM construction). It has
no approval controls; approval happens only on the Core's Unix socket:

```sh
./scripts/open-vaikor-app.sh --print
```

---

## Packaging: OCI Containers, Host Installer & VM Disk Image

- **Rootless Podman / OCI Multi-Arch Container (`linux/amd64`, `linux/arm64`):**
  - `Containerfile` builds static `musl` binaries into a non-root (`65532:65532`) distroless runtime image (`core` and `musl` targets) with zero baked-in keys.
  - `docker-compose.yml` provisions an isolated internal `edges` and `model` network topology with separate UIDs for Control (`65532`), Worker (`65533`), and local model server (`65531`).
  - `docker-compose.cloud.yml` adds an opt-in `egress` network exclusively for the Control node.
- **Systemd Host Installer (Debian 13 / Ubuntu 24.04 & 26.04):**
  - `scripts/install-vaikor-host.sh` installs `/usr/local/bin/vaikor` and `/usr/local/bin/vaikor-tui`, provisions dedicated `vaikor` and `vaikor-approver` users via `sysusers.d`/`tmpfiles.d`, and installs the hardened `vaikor-run@.service` unit.
- **Static `musl` Tarball & Bootable Ext4 VM Rootfs Disk Image:**
  - `scripts/build-vm-disk.sh` builds static-pie `x86_64-unknown-linux-musl` binaries, scans for zero embedded RFC 8032 test keys, and outputs `dist/vaikor-linux-amd64-musl.tar.gz`, `dist/vaikor-vm-rootfs.ext4`, and `dist/SHA256SUMS`.

---

## Repository Structure

```text
.
├── docs/
│   ├── vision/VISION.md        Binding 3-layer OS vision & 9 security invariants
│   ├── specs/                  Architecture decisions & layer specifications (0000–0017)
│   └── demo/mcp-server-time/   Annotated MCP capability descriptor overlay
├── spec/
│   ├── schemas/                JSON Schema 2020-12 definitions (https://vaikor.com/spec/schemas/)
│   ├── registries/             Canonical registries (data-classes, effects, intents, residency, refusal-reasons)
│   ├── examples/               Valid and invalid conformance examples
│   ├── test-vectors/           Normative cross-implementation test vectors (v0.3.0)
│   └── validate/               Python schema & semantic validator + test suite
├── runtime/                    Rust Cargo workspace (12 crates: vaikor-core, vaikor-capability,
│                               vaikor-grant, vaikor-verify, vaikor-mcp, vaikor-gateway,
│                               vaikor-log, vaikor-record, vaikor-model, vaikor-cli,
│                               vaikor-guard [bin: vaikor], vaikor-tui [bin: vaikor-tui])
├── ui/shell/                   Offline static A2UI & Trusted UI shell (@vaiev/ui v4 tokens)
├── companion/                  Companion core (surfaces from schemas) and the Tauri v2 app
│                               (vaikor-desktop, vaikor-android)
├── site/                       Import-free WASM verifier and the vaikor.com schema hub build
├── local-training/             Deterministic datasets, validators & bf16 LoRA training for
│                               Model -1 (linguist), Model 0 and Model 1
├── deploy/                     Systemd units, sysusers.d, tmpfiles.d & host provisioning configs
├── scripts/                    CI verification (ci-local.sh), container/compose checks, VM builder
└── demo/                       Automated CI conformance & residency test fixtures (CH & GLOBAL)
```

---

## Specifications Index (`docs/specs/`)

- [`0000-architektur.md`](docs/specs/0000-architektur.md) — Architecture Decisions (`E1–E9`) & System Overview
- [`0001-capability.md`](docs/specs/0001-capability.md) — `VKR-L0` / `VKR-L1`: Core Objects, Capability Descriptor & MCP Binding
- [`0002-grant.md`](docs/specs/0002-grant.md) — `VKR-L2`: Capability Grants, Attenuation, Budgets & Cedar Policy
- [`0003-plan.md`](docs/specs/0003-plan.md) — `VKR-L3`: Declarative Plan Language v0 & Static Verifier
- [`0004-view.md`](docs/specs/0004-view.md) — `VKR-L4`: Declarative A2UI Views & Core-Owned Trusted UI (`SO_PEERCRED`)
- [`0005-core.md`](docs/specs/0005-core.md) — `VKR-L5`: Core Contract, Kill Switch & Hash-Chained Audit Log
- [`0006-exchange.md`](docs/specs/0006-exchange.md) — `VKR-L6`: Trust-Boundary Envelopes & Peer-to-Peer Exchange
- [`0007-egress.md`](docs/specs/0007-egress.md) — `VKR-L7`: Privacy Gateway, Residency Enforcement, Provider Profiles & Anonymization
- [`0008-native.md`](docs/specs/0008-native.md) — `VKR-L8`: Native System, Immutable Boot & Core Compositor
- [`0009-models.md`](docs/specs/0009-models.md) — On-Device Model Ensemble Architecture
- [`0010-deployment.md`](docs/specs/0010-deployment.md) — Deployment Targets (Bare Metal, Host, VM, OCI Container)
- [`0011-agent-bundle.md`](docs/specs/0011-agent-bundle.md) — Verified Agent Bundles (`Identity + Grants + Plans + Modules + Records`)
- [`0012-records.md`](docs/specs/0012-records.md) — `VKR-L0`: Typed Records, `dcbor` Encoding, Provenance & Retention
- [`0013-cbor-plans-ifc.md`](docs/specs/0013-cbor-plans-ifc.md) — `VKR-L3`: `dcbor` Plans, Owner Signatures & Cedar Information Flow Control
- [`0014-bundle-package.md`](docs/specs/0014-bundle-package.md) — `vkr.bundle/v0` Distributable Bundle Package
- [`0015-swarm.md`](docs/specs/0015-swarm.md) — `VKR-L6`: Multi-Edge Owner Swarm (`S1–S16`), Drift Revocation & Worker Culling
- [`0016-companion-swiyu-iso27090.md`](docs/specs/0016-companion-swiyu-iso27090.md) — Cross-Platform Companion, QR/Passkey/`swiyu` Pairing, `@vaiev/ui` v4 & ISO/IEC 27090
- [`0017-intent-linguist-canvas.md`](docs/specs/0017-intent-linguist-canvas.md) — Intent Catalog, Companion Linguist (Model -1), Morphing Canvas & Browser Verifier

The plan from `v0.2.0` to `v1.0.0` is in [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## How Vaikor Is Built

Vaikor is written by one maintainer with the help of AI coding assistants (currently Claude Code and OpenAI
Codex). We say this openly because a project about trustworthy agents should be plain about how it is made.

- **The maintainer decides.** Direction, specifications, security rules and every merge are decisions of the
  maintainer. Assistants draft code, tests and documentation from written specifications and work packages.
- **Every change is reviewed and signed.** No change lands without the maintainer's review. Each commit carries
  the maintainer's DCO sign-off, and the maintainer is responsible for it like for code typed by hand.
- **Checks do not trust the author.** The specifications lead the code; tests, the plan verifier, the static
  checks and CI run on every change whoever wrote it. A second, independent assistant reviews larger changes
  before the maintainer does.
- **Private data stays private.** Private training corpora stay on the maintainer's machine; they are never
  committed or published, and remote coding agents run on a separate machine that holds none of them.

Contributions made with AI assistance are welcome under the same rules; see
[CONTRIBUTING.md](CONTRIBUTING.md#ai-assisted-contributions).

---

## License

- **Specifications & Documentation:** [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE)
- **Runtime, Schemas, Validator & Code:** [Apache License, Version 2.0](LICENSE-CODE)
- **Provenance & Attribution:** See [NOTICE](NOTICE)
