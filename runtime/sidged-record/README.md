# sidged-record

Status: implemented; used by `sidged record` and `sidged guard`.

SDG-L0 spec 0012 primitives: canonical dCBOR, Record structure,
Ed25519 signing and configured Core trust checks, digest/identifier, retention,
and class resources, plus the offline `store::Store`.

`Record::parse` checks structure only; `Record::check` also checks authenticity
against a caller-configured list of trusted Core `did:key` values. Parsing does
not establish trust. `Record::sign` signs every member except `sig`.
`Record::expired` uses the process clock; its private comparison helper supports
test harnesses only. The store uses `expired` and enforces deletion or
tombstoning before returning content.

`derive_record_labels` re-exports the existing shared implementation in
`sidged-core`; inputs must come from Core read tracking. No derivation
implementation is duplicated here. Grant resource coverage remains in
`sidged-grant`.

The encoder accepts `serde_json::Value`, rejecting floating-point numbers and
non-NFC strings rather than normalizing them. The decoder checks canonicality
by re-encoding and comparing bytes. Both limit nesting to 128 levels to bound
stack use. JSON must be parsed without rounding integers to floating point;
values already rounded by an upstream JSON parser cannot be recovered.

`cargo test -p sidged-record --test vectors -- --nocapture` recursively discovers
all `dcbor-*` and `record-*` operations in `spec/test-vectors`, plus record
coverage vectors. No profile skips are currently required or permitted; new
unavailable profiles fail explicitly. Counts: dcbor-encode 13, dcbor-decode 10,
record-check 14, record-digest 1, record-retention 4, record-derive 7,
record-resource 4, resource-covers 5 (58 total).


`Store::open(directory, core_seed, trusted_core_keys)` holds exclusive locks on
both the store and its signed `audit.log`. `Store::open_with_log` selects an explicit chain path while retaining the store lock.
Records live in `records/<digest>` as
canonical dCBOR including their signature. Store paths and keys are Core-owned
configuration. Like the existing local audit chain, this does not defend against
an operator replacing or rolling back the state directory.

The API offers `write`, `read`, `delete`, `set_retention`, `import`, and
`expire_sweep`. Every attempt appends to the existing signed hash chain before
returning content or changing records. A broken chain or failed append refuses
the operation. Record bytes are written to a temporary file, synced, renamed,
and followed by a directory sync; deletes also sync the directory. Audit allows
are durable intent records: a crash or filesystem error after append can leave
an intent without its effect. Retention changes return a new signed digest and
remove the old address before installing the replacement; a crash between these
two durable steps can lose the Record but cannot retain the old address.

Each user operation takes `Access`: a presented signed grant, an authenticated
holder, a Core-configured audience and policy. The store verifies presentation
and Core issuer trust on each call, then uses the shared grant authoriser and R9
resource coverage. The action for retention changes is `retain`. `max_uses` caps
replay and reserve signed audit spends keyed by issuer, token id and right index,
including every delegated ancestor. Reservations are durable
before the effect; an interrupted operation can consume a use without completing.
Budget and amount caps still fail closed in this standalone store.
`Access::missing()` always denies. Core retention maintenance has authority from R8 and does not accept a user grant.
No API accepts a caller-supplied production clock. Local reads return typed
Records to the Core; external content still requires the Privacy Gateway.

Every read and write requires a Core step from `begin_step(source, plan)`.
Use `read` with that step, then `write` with the same step for derived writes. The
opaque read set must stay in the Core and is bound to that store instance.
The store retains verified input snapshots, rejects expired inputs,
and sets provenance, class and residency using the shared R10 helper. It refuses
if the helper would erase a known restriction. Disjoint CH/EU restrictions stay
as both tags (an empty allowed-region intersection), never empty tags or “any”.
Ordinary `write` refuses writer-supplied nonempty `derived_from`. Trusted imports
preserve the paired Core's signed provenance instead of re-signing it locally.

R8 expiry deletes the file or atomically replaces it with exactly
`{digest, class, provenance, retention}`. Tombstones have no content or signature
and reads refuse them. Sweep skips completed tombstones and fails closed on
corrupt record files. All malformed imports log the raw-byte SHA-256 digest.

`cargo test -p sidged-record --test store` exercises grant refusals, audit failure,
expiry, sweeps, imports, signatures, policy and Core-observed derivation.
