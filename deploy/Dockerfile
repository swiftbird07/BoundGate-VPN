# The BoundGate image: control plane, node, CLI and mux in one image, so a
# host pulls one image whatever it runs (by the digest a signed release names,
# deploy/prod/update.sh). The binaries are built beforehand for every
# platform (make build-linux in the box, or the CI jobs in
# .gitea/workflows); the image adds only what a node needs on a Linux host:
# ip, nft, CA roots. Nothing else: no curl, no shell tools beyond busybox.
#
# The base is pinned by digest (alpine 3.24.1, released 2026-06-16): a tag
# would give every build whatever it points at that day. A newer one after
# the project's 14-day cooldown: the digest from
# https://hub.docker.com/_/alpine/tags (the index digest, both platforms).
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
# The packages come first, before any ARG: a build argument in scope is part of
# a RUN's environment, and REVISION differs with every commit. Up here the layer
# is the same for every build and comes from the builder's cache - which matters
# for arm64, where apk runs under QEMU emulation.
RUN apk add --no-cache iproute2 nftables ca-certificates \
 && mkdir -p /var/lib/boundgate /var/log/boundgate /etc/boundgate /run/boundgate
ARG TARGETARCH
# the public source; ghcr.io also uses this label to show the package on that repository
ARG SOURCE=https://github.com/swiftbird07/BoundGate-VPN
ARG REVISION=unknown
LABEL org.opencontainers.image.source=$SOURCE \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.licenses=MIT \
      org.opencontainers.image.title="BoundGate" \
      org.opencontainers.image.description="Device-bound zero-trust overlay: control plane, node, CLI and mux"
COPY bin/linux_${TARGETARCH}/boundgate-control bin/linux_${TARGETARCH}/boundgate-node \
     bin/linux_${TARGETARCH}/boundgatectl bin/linux_${TARGETARCH}/boundgate-mux /usr/local/bin/
# A node by default; compose files pick the binary with `command:` and the
# user with `user:` (the control plane and the mux do not run as root).
CMD ["boundgate-node", "-config", "/etc/boundgate/node.yaml"]
