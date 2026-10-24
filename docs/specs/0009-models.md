# 0009 – On-device model ensemble

> **Status:** Stub. Direction from vision section 6 (2026-10-15, 02:21). Not a layer, and not a conformance target until the roadmap phase that implements it says so.
> **Date:** 2026-10-15
> **Spec:** Model ensemble (cross-cutting; not SDG-L0–L8)
> **Basis:** [VISION.md](../vision/VISION.md) section 6 and invariant 1 in [0000-architektur.md](0000-architektur.md).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174) when they appear in capitals.

Sidged keeps an ensemble of models on the device. They propose. The Core decides. The choice of weights is still open. This stub names the roles. It does not vendor a checkpoint and it does not add a crate.

## 1. Boundary

**R1.** Every model in the ensemble MUST stay outside the security boundary. A proposal is data until the verifier has checked it. *Rationale: invariant 1 and invariant 3. Vision section 6 repeats both for the ensemble.*

**R2.** A model MUST NOT hold a grant, draw Trusted UI, or open a path around the Privacy Gateway. *Rationale: invariants 2, 4, and 5. Routing a prompt to a weight file is not authorization.*

## 2. Roles

The ensemble has these roles. Further specialist models MAY be added when a task needs one. Adding a specialist does not move it inside the Core.

**R3.** An embedding model MUST run on the device and MUST be small enough for an edge device. It proposes intent routes, record search hits, and capability matches. The example named in the vision is EmbeddingGemma 2 (`google/embeddinggemma-2`): about 271 million parameters, multimodal over text, image, audio, and video, 768-dimensional embeddings, task prompts, and fine-tunable with sentence-transformers. That checkpoint is an example. A later choice MAY replace it. A replacement MUST still be a small on-device embedding model used only to propose. *Rationale: the vision leaves the selection open and still fixes the role. Matching a capability is not a grant.*

**R4.** The router/personal model MUST be the model that proposes plans and learns preferences. It MUST run on the device in local mode. *Rationale: vision sections 1 and 6. The hosted `OpenAiPlanner` calls a remote endpoint. It is not this role. Remote stand-ins are egress under SDG-L7 until this role exists.*

**R5.** The builder model MAY produce a view, a plan, or a WASM module on demand. A view it produces MUST stay declarative (SDG-L4). A plan it produces MUST pass the verifier before any step runs (SDG-L3). A WASM module it produces MUST run only in the WASM sandbox, with at most the rights of the task that asked for it (invariant 6). *Rationale: the builder writes artifacts. The Core still checks them. Generation is not execution.*

**R6.** A call from any role to a provider off the device MUST go through the Privacy Gateway and MUST produce a privacy report. Local mode MUST refuse that call. *Rationale: invariants 5 and 7. "On device" is the default. A specialist that only exists as an API is egress, not a local role.*

## 3. Out of scope

- Downloading, fine-tuning, or serving `google/embeddinggemma-2`. The example is a name and a size, not a dependency of this repository.
- Choosing the final weights. The vision says that choice is open.
- A runtime crate for the ensemble. Phase 11 adds no runtime code.
- The VPS. It has 1 vCPU and 2 GB of RAM and no GPU. The ensemble is outside that workbench.
- Grant tokens, the plan grammar, and Trusted UI drawing. Those stay in SDG-L2, SDG-L3, and SDG-L4.
