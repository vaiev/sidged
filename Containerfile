# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# Multi-stage, multi-arch (linux/amd64, linux/arm64) image for Sidged v1
# (V1 spec L1). The builder cross-compiles on the build platform; only the
# runtime stage is per target. Build per platform, e.g.:
#   podman build --platform linux/arm64 --target core \
#     --build-arg SIDGED_GIT_SHA="$(git rev-parse HEAD)" -t sidged-core .
# Targets: core, musl (static binary export only).
# No keys or secrets are baked in: keys are mounted at runtime under /keys.

# Builder: Alpine (musl), always on the BUILD platform; it cross-compiles
# for TARGETARCH (rust musl target, clang + lld with an Alpine musl sysroot
# of the target arch), so qemu only runs the final stage's smoke test.
# rust:1.89.0-alpine3.22 matches rust-toolchain.toml; pinned by index digest.
FROM --platform=$BUILDPLATFORM docker.io/library/rust:1.89.0-alpine3.22@sha256:4b800f2e72e04be908e5f634c504c741bd943b763d1d8ad7b096cc340e1b5b46 AS build
ARG TARGETARCH
# Versions pinned for reproducibility (Alpine 3.22 main). alpine-keys carries
# the per-arch signing keys for the target sysroot.
RUN apk add --no-cache musl-dev=1.2.5-r13 clang20=20.1.8-r0 lld20=20.1.8-r0 alpine-keys=2.5-r0
RUN case "$TARGETARCH" in \
      amd64) echo "x86_64 x86_64-unknown-linux-musl x86_64-alpine-linux-musl" ;; \
      arm64) echo "aarch64 aarch64-unknown-linux-musl aarch64-alpine-linux-musl" ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac > /target \
 && read -r apkarch _ _ < /target \
 && apk add --root /sysroot --arch "$apkarch" --initdb --no-cache --no-scripts \
      --keys-dir "/usr/share/apk/keys/$apkarch" \
      -X https://dl-cdn.alpinelinux.org/alpine/v3.22/main musl-dev=1.2.5-r13 >/dev/null
WORKDIR /src
COPY rust-toolchain.toml ./
COPY runtime ./runtime
# Files compiled in via include_str! (data-class registry, MCP demo tools).
COPY spec/registries ./spec/registries
COPY docs/demo/mcp-server-time ./docs/demo/mcp-server-time
# .git is not in the build context; the commit comes in as a build arg and
# build.rs falls back to "unknown" if it is not a full 40-char SHA.
ARG SIDGED_GIT_SHA=unknown
ENV SIDGED_GIT_SHA=${SIDGED_GIT_SHA} \
    RUSTUP_TOOLCHAIN=1.89.0 \
    CARGO_INCREMENTAL=0
# Trust split for caches. This committed file is the trusted build
# (push to main, schedule, release, workflow_dispatch): no cache mounts, and
# CI also passes --no-cache, so nothing a pull-request build wrote can reach
# a trusted image. target/ is deleted in the same RUN, so it never lands in
# a layer. Pull-request builds run scripts/containerfile-scope.sh pr<N>,
# which rewrites the two marked lines below into cache mounts with literal
# per-PR ids (sidged-cargo-reg-pr<N>, sidged-cargo-target-pr<N>); trusted
# builds never mount those. Literal ids avoid relying on build-arg expansion
# inside --mount options.
# sidged-cache: run
RUN read -r _ triple clang_target < /target \
 && rustup target add "$triple" \
 && env_triple="$(echo "$triple" | tr 'a-z-' 'A-Z_')" \
 && export "CC_$(echo "$triple" | tr '-' '_')=clang --target=$clang_target --sysroot=/sysroot" \
           "CARGO_TARGET_${env_triple}_LINKER=clang" \
           "CARGO_TARGET_${env_triple}_RUSTFLAGS=-C link-arg=--target=$clang_target -C link-arg=--sysroot=/sysroot -C link-arg=-fuse-ld=lld" \
 && cargo build --manifest-path runtime/Cargo.toml --locked --release -p sidged-guard -p sidged-tui --target "$triple" \
 && install -D -m 0555 "runtime/target/$triple/release/sidged" /out/sidged \
 && install -D -m 0555 "runtime/target/$triple/release/sidged-tui" /out/sidged-tui \
 && rm -rf runtime/target

# Static musl fallback artifact: `--target musl --output type=local,dest=dist`
# (or podman build ... -o dist) yields dist/sidged and dist/sidged-tui.
FROM scratch AS musl
COPY --from=build /out/sidged /sidged
COPY --from=build /out/sidged-tui /sidged-tui

# Minimal runtime: distroless static, non-root (uid 65532), no shell.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime
COPY --from=build /out/sidged /usr/local/bin/sidged
COPY --from=build /out/sidged-tui /usr/local/bin/sidged-tui
USER 65532:65532
WORKDIR /home/nonroot
VOLUME ["/keys"]
ENTRYPOINT ["/usr/local/bin/sidged"]

# Core image; Edge 1 and Edges 2..n run this same signed image (V1 spec).
FROM runtime AS core
LABEL org.opencontainers.image.title="sidged-core" \
      org.opencontainers.image.source="https://github.com/vaiev/sidged" \
      org.opencontainers.image.licenses="Apache-2.0"
