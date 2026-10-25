# 0007 – Egress and providers (VKR-L7)

> **Status:** Draft for the hosted gateway path (R1–R5). OHTTP remains out of scope.
> **Date:** 2026-10-15
> **Spec:** VKR-L7 Egress and Provider
> **Basis:** [VISION.md](../vision/VISION.md) sections 1, 4, and 5 (invariants 5 and 7), and [0000-architektur.md](0000-architektur.md).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174) when they appear in capitals.

Egress is any byte that leaves the runtime toward a provider, a peer, or a network. The Privacy Gateway is the only path.

## 1. Gateway

**R1.** Every egress MUST pass through the Privacy Gateway. A model call or a planner call to a provider is egress. *Rationale: invariant 5. The hosted HTTP client lives in `vaikor-gateway::send`. The planner calls that function.*

**R2.** The gateway MUST refuse egress while the runtime is in local mode. The gateway MUST own a process-wide, one-way local-mode latch. `--local`, boolean `config.local = true`, and `VAIKOR_LOCAL=1` MUST enable it at startup, before planning; no caller or later setting may disable it. A present non-boolean `config.local` MUST be refused. `VAIKOR_LOCAL` unset or exactly `0` means online unless already latched; exactly `1` means local; every other value (including empty or non-Unicode values) MUST be refused. `send()` and execution preflight MUST read the latch. *Rationale: invariant 7. `vaikor run --local`, `config.local`, and `VAIKOR_LOCAL=1` set it. A remote planner and an egress plan step are both refused before a socket opens.*

**R3.** The gateway MUST apply the provider profile (P0–P3) and the residency tags before the bytes leave. A profile or a residency the gateway cannot evaluate MUST be a refusal. Missing or empty data/capability residency declarations MUST deny egress, including loopback. `unrestricted` MUST be explicitly declared to permit GLOBAL processing; CH, EU, and CH-EU MUST deny GLOBAL, including when combined with `unrestricted`. Tags combine by intersection. *Rationale: residency is bound to the destination origin and provider id through a gateway registry (currently HTTPS api.infomaniak.com:443 → CH and HTTPS generativelanguage.googleapis.com:443 → GLOBAL (no residency guarantee), and HTTPS api.open-meteo.com:443 → GLOBAL (Open-Meteo public weather)). Unknown remote destinations refuse all data; the optional caller region must agree with the registry and cannot establish residency. The registry moves to provider manifests in L7; registry-derived report metadata is deferred until that schema is defined. Planner and execute use the same configured provider id. Redirects are refused, all non-loopback HTTP is refused (only loopback IP literals qualify; localhost is not trusted via DNS), and response bodies are limited to 1 MiB. Profile enforcement remains partial: P0–P3 names are accepted, and Gemini Developer API requires P0; `effective` stays null until profile verification and enforcement are implemented in the L7 provider-profile phase.*

The Gemini Developer API registry entry uses origin `https://generativelanguage.googleapis.com`, OpenAI-compatible base path `/v1beta/openai`, and endpoint `/v1beta/openai/chat/completions`. GLOBAL is destination metadata, not a residency tag or a CH/EU guarantee. Public data explicitly tagged `unrestricted` MAY use this destination; CH, EU, and CH-EU restrictions MUST refuse it. Infomaniak remains the CH provider. Google describes a global model pool in its [location documentation](https://firebase.google.com/docs/ai-logic/locations), and its [API terms](https://ai.google.dev/gemini-api/terms) permit transient storage or caching in countries where Google or its agents maintain facilities.

The xAI registry entry (amendment, v1 spec; implemented in `vaikor-gateway`) uses provider id `xai`, origin `https://api.x.ai` (port 443), OpenAI-compatible base path `/v1`, and endpoint `/v1/chat/completions`. Its destination class is GLOBAL (no residency guarantee); GLOBAL is destination metadata, not a residency tag. Only explicitly `unrestricted` payloads may pass the residency check for this destination; CH, EU, and CH-EU restrictions MUST refuse it. Residency is separate from the P0–P3 provider profile. xAI uses profile **P0** (unverified). **Decision record:** Decided by WOUFbot under the standing autonomy Roni granted (2026-10-16 10:29 "du darfsch alles selber mache", 11:19 "selbständig"); delegated, not an explicit P0 decision by Roni. xAI publishes no Vaikor provider manifest, so no P1–P3 claim is possible, matching Gemini Developer API. P0 changes no residency rule. `vaikor-gateway` implements this entry: it requires profile P0, accepts only `/v1/chat/completions` with a JSON object body and no query, refuses before transport otherwise, and emits one privacy report per call. The API key comes from a file (`VAIKOR_API_KEY_FILE`); `VAIKOR_API_KEY` in the environment is refused for xAI, and the key never enters reports, errors or the audit log. §5.1 (R7–R9, including standing approval) and §5.3 anonymization apply unchanged. Redirects MUST remain refused. *Rationale: a delegated standing-autonomy decision registers a GLOBAL destination with the unverified profile P0 and does not relax the existing egress checks.*

Hosted guard planner requests MUST preserve all residency restrictions declared by the catalog included in their prompt. A missing or empty declaration on any included capability MUST deny the planner request and produce a deny audit entry before any network request. Literal loopback destinations MAY receive explicitly `unrestricted` data, but MUST refuse geographic restrictions because their residency is unknown. A scenario's optional `config.task` supplies its task text; it does not grant authority.

## 2. Privacy report

**R4.** Each egress MUST produce one machine-readable privacy report for that call. The report's identifier, time, provider, and payload binding MUST be those of the call. *Rationale: invariant 5. The hosted id digests the provider, the call time, the plan step, and the payload.*

**R5.** A call that does not produce a report MUST NOT leave the runtime. *Rationale: the report is part of the egress, not a log line written afterwards when convenient.*

## 3. OHTTP

**R6.** Provider traffic that the profile says to hide from the network MUST be able to leave over OHTTP. *Rationale: the vision names OHTTP in L7. This stub does not choose a relay or a key schedule. The implementing phase does, after the gateway is the only path.*

## 4. Out of scope

- The report schema already drafted for the hosted prototype. Phase 15 says which fields become normative.
- Peer envelopes and the mesh (VKR-L6).
- A local router model. The vision requires the model that proposes plans to be local. Until that model exists, every remote planner call is egress under R1.
- OHTTP relays, key configuration, and test vectors.

## 5. Guard startup and enforcement boundary

Guard MUST resolve local mode first, then open and exclusively lock a writable signed audit log (refusing a missing log/key), then check the real planner destination URL/host, provider and region using the gateway destination checks. Before planner egress, Guard MUST verify the presented grant and durably reserve grant use and budget under 0002 R20–R21, recording decision `reserve`, then persist a signed planner-intent (`attempt`) entry, then call the planner. A destination denial MUST NOT spend uses or budget. A started planner attempt consumes one use even if planning fails; its durable reservation also remains spent after a crash. Budgets MUST be enforced on every guard step, including steps without effects. A reservation is not human approval; when remote planner egress needs human approval is settled in §5.1. Planner privacy reports and refusals MUST enter the audit chain, including reports from failed calls. Privacy-report audit events carry the serialized report in `privacy_report`. Destination preflight (local mode, provider profile, residency) MUST precede approval. The audit lock MUST remain held through execution and persistence. Loopback approval control connections MUST require a parsed IP socket address whose IP `is_loopback()`; hostnames and wildcard/public addresses are refused.

Catalog effects are untrusted claims (VISION invariant 3). The current executor generates reports and decisions; it does not dispatch capability code or MCP network transports. Any future MCP/sandbox transport MUST enforce egress through the gateway independently of declared effects, with no ambient network access. The hosted planner transport already uses gateway `send()` and its latch. This requirement must be retained when capability dispatch is implemented.

### 5.1 Model-call approval policy (owner decision, 2026-10-15)

This section settles the open owner decision in §5 and §6. It does not relax invariant 2 or 4. Grant and audit apply to every model call, and a reservation (0002 R20–R21) is still not human approval.

**R7.** *Local planner calls.* A planner or model call that runs on the device, with no egress (local mode, or a loopback model that the registry marks `local`), MUST NOT require human approval. It MUST still present a grant that covers the planner capability, reserve uses and budget as in §5, and append its audit entries. *Rationale: there is no export to approve. Invariants 2 and 6 still hold.*

**R8.** *Cloud model calls: first use per (provider, task type).* A call to a remote provider MUST require the owner's approval over the Trusted UI channel (0004 R8–R9; 0005 R3) the first time for each pair (`provider` id from the gateway registry, `task_type`). The approval MUST record a limit: a call count, a budget amount, or both, plus an expiry no later than the grant's. The Core MUST store the approval as a **standing approval**: Core control state of kind `core.standing-approval`, signed by the Core, carrying the approval's audit entry digest. It MUST be keyed by (`provider`, `task_type`, owner `did:key`). It is not a data Record and has no data class. Reading it is a gateway lookup, not a step read, so it MUST NOT enter the step read log and MUST NOT affect check A (R11). *(An `adaptation` class would be local-only under R9 and block every later call.)*
- **R8s.** *Standing scope.* A first-use or over-limit model-call request on the Trusted UI channel MUST show a canonical **standing scope**: `{"standing": true, "provider": …, "task_type": …, "limit": {"calls": n, "budget": m}, "expiry": <RFC 3339>}`. Its `scope_digest` is the SHA-256 (hex) of the RFC 8785 canonical JSON of that object. The request and the answer line carry `scope_digest` as a sixth binding field (0004 R9b). The Core MUST store that digest with the standing approval. A later call reuses the approval only if the stored `scope_digest` equals the digest of the scope recomputed from the stored values, and its `provider` and `task_type` equal the call's. A plain step approval (0004 R9 without `scope_digest`) MUST NEVER become standing; it covers that one call only.
- **R8r.** *Revocation.* The owner MAY revoke a standing approval at any time on the Trusted UI channel. The kill switch (0004 R8) MUST revoke every standing approval. A revocation MUST append its audit entry first and then take effect immediately, before any further model call. If the append fails, the approval is still treated as revoked (fail closed).
- **R8a.** Later calls for the same pair MUST run without a prompt while all of these hold. This is the standing-approval exception of 0004 R8a and 0005 R3a (owner decision, roenu, 2026-10-15): the standing approval is valid, unexpired and not revoked, the grant covers the call, and the counters plus this call stay within the approved limit. The counters are booked durably before connect, as in §5.
- **R8b.** A call that would exceed the approved limit MUST ask the owner every time. It MUST NOT widen the stored limit unless the owner explicitly chooses to. A missing, expired, or revoked standing approval means the call is first-use again.
- **R8c.** `task_type` MUST be the Core's classification of the step: the plan step's capability id, or the planner's fixed id `planner`. It MUST NOT come from the model's text.
- **R8d.** The anonymization check (§5.3) runs on every call, approved or not. An approval never permits a payload that fails §5.3.

*Rationale: owner decision. Remote egress is an export (invariant 5), so the owner sees the first one per destination and purpose. After that, the grant limit is the guard, not repeated prompts. The first-use approval MUST come from a separate approver uid, as for every consequential step (0004 R9 amendment, R9c; 0005 R3).*

**R9.** *Sensitive data stays local.* A payload whose Core-recorded input classes (§5.3, check A) include a class marked `local-only` in owner policy MUST be refused for every remote destination with `data-class-forbidden`. No approval, limit, or model label overrides this. Without an owner policy, the local-only set is `health`, `biometric`, `adaptation`, and `secrets` (data-classes registry). Data tagged `CH` reaches only CH destinations (0001 R8c). *Rationale: invariants 3 and 5.*

### 5.2 User subscriptions

**R10.** An owner MAY register an existing provider subscription for larger tasks. The registration MUST name the provider id, the subscription's limit (requests, tokens, or money per period, as the owner states it), and a credential **reference**.
- **R10a.** The credential MUST stay with the user: in the OS keychain or a user-held secret store, read by the gateway at send time. It MUST NOT be written to the Core's store, a Record, a plan, a bundle (0014), a grant, the audit log, or a privacy report. Reports and audit entries carry only the reference id and the provider.
- **R10b.** Budget for calls on the subscription MUST be counted against the subscription limit in the durable ledger (0002 R20–R21), in addition to the grant budget. The tighter of the two applies. An exhausted subscription refuses before connect with `budget-exceeded`.
- **R10c.** R8, R9 and §5.3 apply unchanged. A subscription changes who pays, not what may leave.

*Rationale: invariants 5 and 9 (no secrets in reports or audit logs) and invariant 2. A bundle that brings its own credential is refused (0014).*

### 5.3 Core-checked anonymization

The local model is asked to anonymize outgoing payloads. The Core MUST NOT trust that claim (invariant 3). A payload is **anonymized** for this spec only if all of the checks below pass, evaluated by the Core before egress, after R7–R10 and before `send()`. §5.3 applies only to remote destinations; a local call (R7) does not leave the device. A model label such as `"anonymized": true` MUST be ignored.

**R11.** *Checks, in order. The first failure refuses.*

- **A. Input classes, from the Core's record.** The set of data classes is the union of the classes of every Record and input the step read, as recorded by the Core in its step read log (0012 R10, 0013). It is never taken from the model or the payload. Refuse with `data-class-forbidden` if:
  - any class is local-only (R9);
  - any class is above the owner's export threshold for this destination; or
  - any input has no class.

  The **export threshold** is an owner-policy set of classes allowed to leave per destination class (`CH`, `EU`, `GLOBAL`). Default: only `query` and `documents.text` for every destination class. A class matches by dot boundary (`health` covers `health.records`, as in `vaikor-verify/src/plan.rs:237`).
- **B. Residency.** The derived residency tags (0012 R10, 0001 R8e) MUST pass 0001 R8 for the destination class: missing or empty tags fail closed, and only `unrestricted` reaches `GLOBAL`. Refuse with `residency-unsupported`.
- **C. Size.** The payload body MUST NOT exceed the owner's `max_payload_bytes` (default 32 KiB) for the destination. Refuse with `policy-denied`.
- **D. Deterministic detector.** The detector set (R12) MUST find no match in the UTF-8 payload after NFKC normalization. Refuse with `data-class-forbidden`, naming the detector id but never the matched text.

**R12.** *Detector set.* The detector set is versioned. Version `vkr.pii/1` is exactly the set below, applied as case-insensitive regular expressions with no network or model access:

| id | Matches |
|---|---|
| `email` | `[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}` |
| `phone` | `\+?\d[\d ().-]{7,}\d` with at least 9 digits |
| `iban` | `\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b` |
| `ch-ahv` | `\b756[.\s]?\d{4}[.\s]?\d{4}[.\s]?\d{2}\b` |
| `card` | a run of 13 to 19 digits (spaces or dashes allowed) that passes the Luhn check |
| `ipv4` | `\b(?:\d{1,3}\.){3}\d{1,3}\b` |
| `secret` | `-----BEGIN [A-Z ]*PRIVATE KEY-----`, `\bsk-[A-Za-z0-9_-]{16,}`, `\bgh[pousr]_[A-Za-z0-9]{20,}`, `\bAKIA[0-9A-Z]{16}\b`, `\bxox[abpr]-[A-Za-z0-9-]{10,}` |

- **R12a.** A change to the set or to a pattern MUST bump the version (`vkr.pii/2`, …). The gateway MUST refuse egress (`policy-denied`) if its configured detector version is unknown to it.
- **R12b.** Owner policy MAY add detectors (ids starting with `x-`), which become part of the reported version (`vkr.pii/1+x-…`). It MUST NOT remove the base set.
- **R12c.** *Residual risk.* The detectors are deterministic and incomplete. Names, free-text health facts, and re-identifiable combinations are not detected. A false negative is a known residual risk. Check A, not the detector, is the primary control for sensitive classes. The detector is a backstop for leaks into a payload that check A allowed.

**R13.** *Audit.* Every outcome of §5.3, permit or refuse, MUST append an audit entry before `send()` (or before returning the refusal). The entry MUST hold:
- `payload_sha256`: SHA-256 of the exact bytes to be sent;
- `detector_version`;
- the matched detector ids (on refuse);
- the input class set from check A;
- the derived residency tags;
- the destination class and provider id;
- the standing approval digest and its `scope_digest` (R8), if any;
- the subscription reference id (R10), if any.

It MUST NOT contain the payload or the matched text. If the append fails, the call MUST be refused (fail closed, as in §5).

*Rationale: invariants 3, 5, 9. The model's claim is not checked by the model. Vectors: `egress/anonymization.json` (operation `egress-check`).*

## 6. Review follow-ups

- Owner decision (resolved 2026-10-15, §5.1): local planner calls need no approval; remote calls need first-use approval per (provider, task type) with a limit. A grant reservation is still not human approval (invariant 2).
- Complete L7 provider-profile enforcement and populate verified `effective` metadata.

Plan-step reports are persisted in the corresponding signed audit event. The hosted executor binds these reports to serialized proposed arguments and marks `payload_binding` as `proposed-arguments`; it does not claim to have sent a provider request. Reports contain metadata and digests, never argument values.

Gemini Developer API uses profile **P0** and **GLOBAL** residency; only explicitly `unrestricted` payloads are permitted. Configure the billing project with `VAIKOR_GEMINI_PROJECT` (or `provider_project` in `config.json`); missing or blank values refuse before any request. This is a required configuration declaration, not verification that billing is enabled. Grounding (`google_search`, `googleSearchRetrieval`, `grounding`), explicit caching (`cachedContent`, `cached_content`), File API inputs/uploads, and Live API/session resumption are unsupported and refused before transport. The reviewed endpoint is `/v1beta/openai/chat/completions`.

CH/EU support is deferred to Vertex AI regional endpoints with its own provider, residency and retention review. The Developer API does not provide that guarantee.
