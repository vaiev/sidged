# Global Unrestricted Residency Conformance Fixture (`demo/public-weather`)

This directory is an automated CI conformance and residency test fixture exercised by `runtime/sidged-guard/tests/`.

It models a public, non-personal weather lookup for Zurich city with explicit `unrestricted` residency tags on every capability (`tools.json`, `grant.json`, `policy.cedar`, `stub-plan.json`). It exercises static plan verification, capability grant chain verification, Cedar policy evaluation, Privacy Gateway preflight, and signed Record provenance (`urn:sidged:record:x-public/weather`).

## Running the fixture manually

From the repository root:

```sh
cargo build --manifest-path runtime/Cargo.toml -p sidged-guard
./runtime/target/debug/sidged keygen /tmp/public-weather-keys
SIDGED_PROVIDER=stub ./runtime/target/debug/sidged guard demo/public-weather --keys /tmp/public-weather-keys \
  --approve unix:/run/sidged/approval/control.sock --approve-uid 65540 \
  --log /tmp/public-weather-audit.log --log-key /tmp/public-weather-keys/issuer.key
```

Consequential steps require approval through the Trusted UI Unix socket (`0004 R9/R9c`); without an approval channel or in local mode (`SIDGED_LOCAL=1`), execution refuses them before connecting.
