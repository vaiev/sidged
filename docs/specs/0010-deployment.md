# 0010 – Deployment targets

> **Status:** Draft v0.1. OCI container (`Containerfile`, `docker-compose.yml`), Linux host systemd installer (`scripts/install-sidged-host.sh`), and VM rootfs image builder (`scripts/build-vm-disk.sh`) are implemented.
> **Date:** 2026-10-15
> **Spec:** Deployment targets (cross-cutting; not SDG-L0–L8)
> **Basis:** [VISION.md](../vision/VISION.md) section 6, decision E9, and [0008-native.md](0008-native.md).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174) when they appear in capitals.

Sidged is an OS for edge devices. The same stack runs on more than one kind of host. This stub names the targets. SDG-L8 still owns the bare-metal image. Packaging is not a second security model.

## 1. Targets

**R1.** A conforming deployment MUST be one of these targets:

| Target | What runs | Kernel |
|---|---|---|
| Bare metal | Sidged is the system on the device, in place of Android or iOS | The image's Linux kernel. Boot and the compositor are SDG-L8 |
| VPS host | The hosted runtime directly on the machine | The host's Linux kernel |
| VM | The hosted runtime in a virtual machine | The guest's Linux kernel |
| OCI container | The hosted runtime as an OCI image | The host's Linux kernel |

*Rationale: vision section 6. One product, four ways to boot the same stack: Linux kernel, then AI runtime, then interface.*

**R2.** Every target MUST present that stack. A container MUST NOT replace the runtime with a classic userland. *Rationale: the arrow in the vision is the product. An OCI image is a package of the runtime, not a different OS.*

## 2. Same invariants

**R3.** Invariants 1–9 MUST hold on every target. A VM boundary or a container boundary MUST NOT waive a grant, the verifier, Trusted UI, or the Privacy Gateway. *Rationale: packaging is not a security boundary. The Core is.*

**R4.** A hardware call, a data call, and a communications call MUST go through a capability and a grant on every target. Device files, sockets, and volumes the host happens to mount are not ambient authority. *Rationale: vision section 6 asks for security-first interfaces for communication, data processing, and hardware calls. Invariant 2 is that rule.*

**R5.** The bare-metal target MUST follow SDG-L8 for direct boot, A/B updates, and the Core-owned compositor. This document does not replace `0008-native.md`. *Rationale: "in place of Android/iOS" is the native image. iOS as a host operating system stays out of scope, as `0000-architektur.md` already says. Sidged is the system instead of those OS families. It is not an app inside them.*

**R6.** The VPS, the VM, and the OCI image MUST carry the hosted runtime, the stepping stone in E9. They MUST NOT be specified as a second product with a weaker Core. *Rationale: hosted, then native. The host service, the VM, and the OCI image are the same runtime in another package.*

## 3. Out of scope

- A Dockerfile, an image build, a VM disk, or a bare-metal installer. Those belong to the phase that implements the target.
- SDG-L8 boot slots, Smithay, and phone hardware. Bare metal points there.
- Running the ensemble of `0009-models.md`. Deployment does not choose weights.
- Public ports on the VPS. The workbench has none. An OCI image built later still runs on loopback there.
