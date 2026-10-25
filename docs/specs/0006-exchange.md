# 0006 – Exchange (VKR-L6)

> **Status:** Stub. Direction from the binding vision (2026-10-15). Not a conformance target until a later phase says so. The VPS has no public ports, so this layer is not a VPS deliverable.
> **Date:** 2026-10-15
> **Spec:** VKR-L6 Exchange
> **Basis:** [VISION.md](../vision/VISION.md) sections 2 and 4, and decisions E1, E7, and E8 in [0000-architektur.md](0000-architektur.md).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174) when they appear in capitals.

Exchange is how a runtime talks to something it does not already trust: another device, another owner, a foreign agent, or a non-Vaikor system. Local calls are not exchange.

## 1. What is signed

**R1.** A call inside one runtime, mediated by the Core, MUST NOT use a signed envelope. *Rationale: E7. The Core is the party that would check a signature it had just produced.*

**R2.** A message that crosses a trust boundary MUST be a signed envelope. The signed bytes MUST be an L0 canonical encoding: JCS or deterministic CBOR (`dcbor`). *Rationale: the vision puts canonical JSON / `dcbor` and signatures on L0. This layer specifies the envelope. It does not define a third canonical form.*

**R3.** This layer MUST NOT specify `dcbor` or JCS. Those encodings are VKR-L0. *Rationale: earlier text in VKR-L3 placed deterministic CBOR on L6. That contradicted the vision. Plans, grants, and descriptors use the L0 encodings. An envelope carries the bytes.*

## 2. Mesh and bindings

**R4.** The Vaikor mesh, when implemented, MUST carry CBOR over QUIC with Noise. *Rationale: the vision names that stack for the mesh the runtime owns. It is not a second envelope format.*

**R5.** A foreign agent MUST attach through the A2A binding. A group MUST use MLS. *Rationale: E1 and E8. A2A and MLS already exist. Vaikor does not invent a group key agreement or an agent card format.*

**R6.** Legacy methods 1–5 MUST stay available as bindings, labelled legacy and unattested. *Rationale: E8, option C. They are how existing apps and services appear. The label stops a verifier from treating them as Vaikor principals.*

**R7.** People reached by email or messaging MUST attach at this boundary, not as modules inside the Core. *Rationale: the vision's two paths. A mailbox is outside the runtime's trust.*

## 3. Out of scope

- The JCS and `dcbor` algorithms (VKR-L0). Grant tokens already sign JCS in `vaikor-grant`.
- Provider egress, privacy reports, and OHTTP (VKR-L7). A provider call is egress even when the bytes are an envelope.
- QUIC, Noise, MLS, and a running mesh. No test vectors in this stub. The roadmap lists the mesh after the hosted security gaps.
- MCP tool annotations (VKR-L1). MCP here is only the attachment of an outside system.
