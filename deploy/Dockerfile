# The BoundGate image: control plane, node, CLI and mux in one image, so a
# host pulls one tag (gitlab.net407.com/sbh/boundgate:latest) whatever it
# runs. The binaries are built beforehand for every platform (make
# build-linux in the box, or the CI job in .gitea/workflows/image.yml); the
# image adds only what a node needs on a Linux host: ip, nft, CA roots.
FROM alpine:3.20
# The packages come first, before any ARG: a build argument in scope is part of
# a RUN's environment, and REVISION differs with every commit. Up here the layer
# is the same for every build and comes from the builder's cache - which matters
# for arm64, where apk runs under QEMU emulation.
RUN apk add --no-cache iproute2 nftables ca-certificates curl \
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
# A node by default; compose files pick the binary with `command:`.
CMD ["boundgate-node", "-config", "/etc/boundgate/node.yaml"]
