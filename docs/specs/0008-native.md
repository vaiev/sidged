# 0008 – Native system (SDG-L8)

> **Status:** Stub. Direction from the binding vision (2026-10-15) and decision E9. Native is the end state. It is not a hosted milestone and it is outside what the VPS can run.
> **Date:** 2026-10-15
> **Spec:** SDG-L8 Native System
> **Basis:** [VISION.md](../vision/VISION.md) sections 1, 4, and 6, and the native-target section of [0000-architektur.md](0000-architektur.md). Packaging other than bare metal is [0010-deployment.md](0010-deployment.md).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174) when they appear in capitals.

Native means the image is the system: kernel, then runtime, then interface. Hosted remains the stepping stone until this layer is implemented.

## 1. Boot and update

**R1.** A native image MUST boot the Linux kernel, then the Sidged runtime, then the interface. It MUST NOT boot a classic userland (desktop shell, app model, app store, package manager, file-manager shell, or separate end-user account logic). *Rationale: E4 and the vision. The kernel stays because drivers are decades of work. Sidged is the OS above it.*

**R2.** Updates MUST be A/B images. A failed boot MUST fall back to the previous slot. Rollback MUST NOT install an image that has been revoked. *Rationale: the vision names A/B updates. A half-applied update must not be the only system.*

## 2. Compositor

**R3.** The Core MUST own the Wayland compositor that draws Trusted UI. A generated view MUST NOT be that compositor. *Rationale: unforgeable Trusted UI. Smithay is the example named in the vision. Naming it does not add the crate.*

**R4.** Hardware MUST be reached through kernel drivers and hardware modules that carry capability descriptors. The model MUST NOT receive ambient device files. *Rationale: invariant 2. A device file would be ambient authority.*

## 3. Devices that are not a full runtime

**R5.** A device that cannot carry a full runtime MUST use a shim. The shim speaks the trust-boundary envelope (SDG-L6) and MUST NOT present itself as a Core. *Rationale: E9. A shim that claims to decide would fake the security boundary.*

**R6.** Phones come last, and only on unlockable hardware. iOS is out of scope as a host. *Rationale: accepted in the native-target section of `0000-architektur.md`. Vision section 6 puts Sidged in place of Android and iOS. That is this bare-metal target, not an app inside those systems.*

## 4. Out of scope

- Building an image, a bootloader, or a compositor in the hosted phases. OCI and VM packages are [0010-deployment.md](0010-deployment.md).
- Smithay as a dependency of `runtime/`. Nothing in the current workspace links it.
- The VPS. It ends on 31 December 2026 and cannot host this layer.
- Hosted crates, the plan verifier, and the Privacy Gateway. They are the stepping stone this layer boots, not a second design.
