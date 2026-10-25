# CH Residency Conformance Fixture (`demo/ch-residency`)

This directory is an automated CI conformance and residency test fixture exercised by `runtime/vaikor-guard/tests/`.

It models a `CH`-residency moderation scenario (`tools.json`, `grant.json`, `policy.cedar`, `stub-plan.json`). `vaikor guard` signs the fixture grant with freshly generated Ed25519 issuer and holder keys, verifies the signature, expiry, holder binding, and attenuation before Cedar, and enforces `CH` residency via `vaikor-gateway` after static plan verification.

No API key is stored here. CI and the default command use the deterministic stub (`stub-plan.json`).

## Running the fixture manually

From the repository root, after `cargo build --manifest-path runtime/Cargo.toml -p vaikor-guard`:

```sh
./runtime/target/debug/vaikor keygen /tmp/ch-fixture-keys
./runtime/target/debug/vaikor guard demo/ch-residency --keys /tmp/ch-fixture-keys \
  --log /tmp/ch-fixture-audit.log --log-key /tmp/ch-fixture-keys/issuer.key
```

Expected counts include one privacy report and a `CH` residency tag on that report. Unregistered or `GLOBAL` destinations are refused before sending.
