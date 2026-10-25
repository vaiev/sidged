# Security policy

Vaikor is a pre-alpha research preview (see the status in [README.md](README.md)). It has had no external security
review yet, and it is not ready to protect real data or real money.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on this repository
(private vulnerability reporting). Do not open a public issue for a vulnerability.

Helpful in a report: the affected component (`runtime/`, `companion/`, `site/`, a specification), the version or
commit, the steps to reproduce, and which of the nine invariants (README) it breaks.

We acknowledge reports within 7 days and agree on a disclosure date with you; credit is given unless you ask otherwise.

## Scope

In scope: the Rust Core (plan verifier, grants, Cedar flow policy, Privacy Gateway, audit log, records), the companion
apps and their single IPC command, the WASM verifier, and the specifications and schemas.

Known, documented limits are not vulnerabilities by themselves: approval in the apps is not yet bound to a hardware-backed
Trusted UI (consequential steps are denied instead), the audit log is tamper-evident for edits but detects truncation
only against an anchored head, and the models only propose (invariant 1). They are tracked in
[docs/ROADMAP.md](docs/ROADMAP.md).
