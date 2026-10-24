# 0015 – Swarm: edges of one owner (proposal)

> **Status:** Draft v0.1. Implemented in `runtime/sidged-cli/src/swarm.rs` (`S1–S16`, `sidged swarm measure`, technocratic worker culling & replacement, and autonomous `SwarmWorkQueue`).
> **Date:** 2026-10-18
> **Spec:** SDG-L6 profile "owner swarm"
> **Basis:** [VISION.md](../vision/VISION.md) section 5 (invariants 1–9), [0006-exchange.md](0006-exchange.md)
> R2 and R4, [0002-grant.md](0002-grant.md), [0005-core.md](0005-core.md), and [0010-deployment.md](0010-deployment.md) §3.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174) when
they appear in capitals.

A **swarm** is a set of Sidged runtimes ("edges") that belong to one owner and cooperate on that owner's
tasks. **Edge 1** holds the owner's personal state, Model Zero and the interface. **Edges 2..n** run work that
Edge 1 delegates. Each edge is a full Sidged Core with its own audit log; there is no shared Core.

## 1. What an edge is

**S1.** An edge MUST be an instance of the same signed `sidged` core image as Edge 1, identified by the image
digest. Edges MUST NOT run third-party worker containers or worker processes outside that image. *Rationale:
v1 spec "Edges 2..n are instances of the signed sidged core container itself". A worker that is not the Core
would be a second trust boundary that no Core checks (invariant 8). Modules arrive only as WASM components in
v1.1 (0011 R6/R7) and then run inside a Core.*

**S2.** Each edge MUST have its own device key and `did:key`, generated on that edge by `sidged keygen` or its
successor. An edge key MUST NOT be copied to another edge, and no repository, image or configuration MAY carry
a default or placeholder `did:key`. *Rationale: a shared or placeholder key makes edges indistinguishable, so a
signature proves nothing (invariants 3 and 9; pre-review checklist "no repo constants for identities").*

**S3.** Every edge MUST enforce invariants 1–9 itself. Membership in a swarm MUST NOT relax a grant check, the
verifier, Trusted UI, the Privacy Gateway or the audit log on any edge. *Rationale: 0010 R3 — packaging and
topology are not the security boundary; the Core is.*

## 2. Enrollment and authentication

**S4.** An edge MUST join a swarm only through an enrollment that the owner approves on Edge 1's Trusted UI
channel (0004 R9). The approval MUST bind the joining edge's `did:key` and its image digest. *Rationale: adding
an edge widens where the owner's tasks run. That is consequential (invariant 4).*

**S5.** Edge 1 MUST then issue the edge a grant (0002) whose audience is that edge's `did:key`, with rights
limited to the delegated capabilities, a budget and an expiry. Enrollment MUST NOT create standing authority
beyond that grant. *Rationale: invariant 2 (no ambient authority). The v1 spec's "no persistent privileges
outside a valid grant".*

**S6.** Edges MUST authenticate each other mutually with their `did:key` device keys over the 0006 R4 mesh
binding (CBOR over QUIC with Noise). An edge MUST refuse a peer whose key is not enrolled or whose enrollment
was revoked. Status such as "online" MUST NOT be shown or recorded for a peer before a completed handshake.
*Rationale: 0006 R4 names the stack; the turnkey plan reported handshakes that were not performed, which the v1
spec forbids ("nothing shown that does not exist").*

## 3. Messages

**S7.** Every message between edges MUST be a signed envelope (0006 R2) that carries the grant authorising it.
The receiving Core MUST verify the envelope, verify the grant chain to the owner, and evaluate the request
against the receiver's Cedar policy with default deny before acting. *Rationale: invariant 3 — a peer's message
is data until the verifier has checked it.*

**S8.** Every received message and every effect it causes MUST be appended to the receiving edge's audit log
before the effect, and the sending edge MUST audit the send. A failed append MUST refuse the message.
*Rationale: invariant 9 and 0005 R6/R7 (audit before effect, append-only chain).*

**S9.** A consequential step MUST be approved on Edge 1's Trusted UI channel by the owner's approver uid. An
edge MUST NOT approve a consequential step for another edge, and an edge without a Trusted UI channel MUST deny
consequential steps. *Rationale: invariant 4 and 0004 R9 (approval only on the Core's channel, by a separate
approver uid).*

**S10.** Egress from any edge MUST pass that edge's Privacy Gateway with a privacy report (0007 R1, R4). A
payload delegated to an edge keeps its data classes and residency tags; an edge MUST NOT send it to a
destination that Edge 1 would refuse. *Rationale: invariant 5. Delegation must not launder residency.*

## 4. Drift and rebuild

**S11.** **Drift** is defined as any of: the running image digest differs from the enrolled digest; the edge's
`did:key` differs from the enrolled key; the edge's audit chain fails verification; or the edge refuses a
measurement request from Edge 1. Edge 1 MUST treat a drifted edge as revoked: its grants are revoked, its
messages refused, and the revocation audited. *Rationale: the v1 spec's "technocratic rule" needs a testable
definition before anything is terminated or rebuilt.*

**S12.** A rebuild MUST be an owner-approved step on Edge 1 (S4) that enrolls a fresh edge from the signed
image with a new `did:key`. Edge 1 MUST NOT control a container engine or a hypervisor directly to do so.
*Rationale: a Core that drives a container engine holds root-equivalent power on the host and breaks the R9c
separation (0004 R9c lists `docker` and `podman` groups as root-equivalent). Rebuild is an operator or
deployment action, recorded and approved, not ambient Core authority.*

**S13.** How the image is signed and how the signature is verified at enrollment MUST be specified (key,
format, revocation) before S11 and S12 can be implemented. *Rationale: "rebuilt from the signed image" is not
checkable today; no spec defines image signing.*

## 5. Topology and network

**S14.** In local mode (0007 R2) the mesh MUST be off: no bind, no listen, no connect to peers. *Rationale:
invariant 7 and 0005 (local mode makes no socket except the configured local model endpoint).*

**S15.** Until 0010 is amended, all edges MUST run on the same host on a private network without published
ports; no edge MAY listen on a wildcard or public address. *Rationale: 0010 §3 (no public ports; loopback
only) and the v1 spec ("same-host compose network only; no published ports").*

**S16.** No edge MAY expose an HTTP or WebSocket API for swarm control or for keys. *Rationale: 0004 removed the
HTTP channel; 0007 R10a keeps credentials with the user; the v1 edge rule excludes gRPC/HTTP2 and WebSocket.*

## 6. Open questions

1. **Cross-host edges.** A LAN or remote edge needs a 0010 amendment (address discovery, NAT, which ports, and
   how a remote edge proves its image). Not part of this proposal.
2. **Core API transport for a GUI.** The v1 spec says the TUI and the GUI shell use "the same Core API" but no
   spec defines its transport. Proposal to decide separately: a Unix socket with `SO_PEERCRED`, read-only, with
   no approval verbs (approval stays on the 0004 R9 channel). Until then the offline UI shell has no live Core
   data.
3. **Measurement.** What Edge 1 may ask an edge to prove (image digest only, or also configuration and module
   set), and how often.
4. **Budgets across edges.** Whether one grant budget is shared across edges or split at delegation.
5. **Owner devices vs. edges.** Whether an owner's phone or laptop is an edge or a peer under 0006 R5/R6.

## 7. Out of scope

- Any implementation, container orchestrator, worker container, or `serve` command.
- Cross-host and remote VM edges (pending a 0010 amendment), and published ports.
- Container engine or hypervisor control by the Core.
- HTTP, WebSocket or gRPC control APIs; key vault endpoints.
- A2A peers of other owners and MLS groups (0006 R5); legacy bindings (0006 R6).
- QUIC, Noise and envelope wire details and test vectors (0006, SDG-L0).
- WireGuard (deferred by the v1 spec).
