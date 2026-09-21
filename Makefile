# All Go and Node commands run inside the `box` dev container (see docs/DEV.md).
GOARCH ?= $(shell uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
COMPOSE = docker compose -f deploy/compose/docker-compose.yml
# Release builds: make VERSION=v1.2.3 ... (the release pipeline does). Anything
# else is "dev" and never updates itself.
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null)
VPKG = gitlab.net407.com/SBH/BoundGate-VPN/internal/version
LDFLAGS = -X $(VPKG).Version=$(VERSION) -X $(VPKG).Commit=$(COMMIT)
BINS = boundgate-control boundgate-node boundgatectl boundgate-mux boundgate-fakeidp boundgate-udpbridge boundgate-embedtest

.PHONY: test-lib apple-core ios-project image image-push rehearsal mac-app mac-sekey release release-next release-mirror release-test setup-test tag-latest-test release-key update-test test-tpm web web-dev web-check web-test build-linux build-darwin build-windows windows-zip test test-race vet fuzz cooldown compose-up compose-down compose-logs setup-dev e2e clean

# The admin SPA (web/) is built into internal/control/web/dist and embedded
# into boundgate-control; build-linux depends on it so the lab image has it.
web:
	@# npm ci removes node_modules itself, and that trips over the container's file sharing (ENOTEMPTY)
	rm -rf web/node_modules
	box sh -c 'cd web && npm ci --no-audit --no-fund && npm run build'

# UI work without a control plane: Vite dev server in the box image, published
# on loopback only (box itself publishes no ports). Open
# http://localhost:$(WEB_DEV_PORT)/?demo for demo data (docs/DESIGN.md).
WEB_DEV_PORT ?= 5183
web-dev:
	docker run --rm -i --init --name boundgate-ui-preview --user "$$(id -u):$$(id -g)" --cap-drop ALL \
	  --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,exec,size=1g --pids-limit 1024 --memory 6g \
	  -v "$(CURDIR)/web":/work -w /work -v paw-box-home:/home/box -v paw-box-cache:/cache \
	  -p 127.0.0.1:$(WEB_DEV_PORT):$(WEB_DEV_PORT) paw-box:latest npx vite --host 0.0.0.0 --port $(WEB_DEV_PORT) --strictPort

web-check:
	box sh -c 'cd web && npx svelte-check --tsconfig ./tsconfig.json'

# policy builder: every generated rule parses back into the same model;
# mesh view: the graph at a moment, rates, timeline and layout (docs/MESH.md)
web-test:
	box sh -c 'cd web && npm test --silent >/dev/null && npm run --silent test:mesh'

build-linux: web
	@mkdir -p bin/linux_$(GOARCH)
	@for b in $(BINS); do \
	  echo "building $$b for linux/$(GOARCH)"; \
	  box env GOOS=linux GOARCH=$(GOARCH) go build -trimpath -ldflags "$(LDFLAGS)" -o bin/linux_$(GOARCH)/$$b ./cmd/$$b || exit 1; \
	done

# The macOS node (M5): cross-compiled in the box, run on the host with
# deploy/macos/dev.sh. The control plane is not built for macOS.
build-darwin:
	@mkdir -p bin/darwin_$(GOARCH)
	@for b in boundgate-node boundgatectl boundgate-udpbridge; do \
	  echo "building $$b for darwin/$(GOARCH)"; \
	  box env GOOS=darwin GOARCH=$(GOARCH) CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/darwin_$(GOARCH)/$$b ./cmd/$$b || exit 1; \
	done

# Windows (M10): service, CLI and tray, cross-compiled in the box (no cgo);
# windows-zip packs them with the install scripts (docs/WINDOWS.md).
WINARCH ?= amd64
build-windows:
	@mkdir -p bin/windows_$(WINARCH)
	@for b in boundgate-node boundgatectl; do \
	  echo "building $$b for windows/$(WINARCH)"; \
	  box env GOOS=windows GOARCH=$(WINARCH) CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/windows_$(WINARCH)/$$b.exe ./cmd/$$b || exit 1; \
	done
	@echo "building boundgate-tray for windows/$(WINARCH)"
	@box env GOOS=windows GOARCH=$(WINARCH) CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS) -H=windowsgui" -o bin/windows_$(WINARCH)/boundgate-tray.exe ./cmd/boundgate-tray

windows-zip: build-windows
	deploy/windows/zip.sh $(VERSION) $(WINARCH) bin/windows_$(WINARCH) dist

test: web-test test-lib
	box go vet ./...
	box env GOOS=windows go vet ./...
	box go test -count=1 ./...

# BoundGateCore.xcframework for the iOS app and its packet tunnel (docs/IOS.md);
# the one target that runs Go on the Mac (~/.local/go-apple)
apple-core:
	VERSION=$(VERSION) apps/ios/core/build.sh

# apps/ios/BoundGate.xcodeproj from apps/ios/project.yml (xcodegen on the Mac)
ios-project:
	cd apps/ios && xcodegen generate

# libboundgate (the apps' core, docs/EMBED.md) as a C archive, driven from C
test-lib:
	box sh -c 'set -e; d=$$(mktemp -d); CGO_ENABLED=1 go build -buildmode=c-archive -o $$d/libboundgate.a ./cmd/libboundgate; \
	  cc -Wall -o $$d/harness cmd/libboundgate/testdata/harness.c -Icmd/libboundgate $$d/libboundgate.a -lpthread -lm; $$d/harness $$d/state; rm -rf $$d'

# TPM-backed device keys against a software TPM (swtpm) on the default
# bridge, where the box can reach it. Not part of `test`: needs Docker.
test-tpm:
	docker build -q -t boundgate-swtpm -f deploy/compose/Dockerfile.swtpm deploy/compose >/dev/null
	-docker rm -f boundgate-swtpm-test >/dev/null 2>&1
	docker run -d --rm --name boundgate-swtpm-test --tmpfs /var/lib/swtpm boundgate-swtpm \
	  --server type=tcp,port=2321,bindaddr=0.0.0.0 --ctrl type=tcp,port=2322,bindaddr=0.0.0.0 >/dev/null
	ip=$$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' boundgate-swtpm-test); \
	  box env BOUNDGATE_TEST_TPM=tcp:$$ip:2321 go test -count=1 -v ./internal/devicekey/tpm2key/; rc=$$?; \
	  docker rm -f boundgate-swtpm-test >/dev/null; exit $$rc

# BoundGate.app (docs/MACOS-APP.md): Go in the box, Swift and codesign on the Mac
mac-app:
	apps/macos/build-app.sh

# A release, from this Mac (docs/RELEASES.md): tag, wait for CI's draft, Mac
# app signed and notarized here, manifest signed with the release key here,
# publish. Without VERSION the next patch version after the highest tag;
# BUMP=minor or major for the others. `make release VERSION=vX.Y.Z` resumes.
BUMP ?= patch
release:
	BUMP=$(BUMP) deploy/release/release.sh $(filter-out dev,$(VERSION))

# only the last step of `make release`: the same signed files onto GitHub
release-mirror:
	deploy/release/mirror-github.sh $(filter-out dev,$(VERSION))

# which version `make release` would make
release-next:
	@BUMP=$(BUMP) deploy/release/release.sh --next

# deploy/release/release.sh against a stand-in for Gitea
release-test:
	deploy/release/release_test.sh

# The release signing key (docs/RELEASES.md). Run it yourself, once. The
# private half stays in private/ (git-ignored; masked in the box) on the
# machine that makes releases, protected by the passphrase ssh-keygen asks for;
# no CI ever gets it. The public half goes into the two release_keys files,
# which you commit: builds accept updates signed by a key listed there.
release-key:
	@test ! -e private/release_signing_key || { echo "private/release_signing_key exists; remove it first if you really want a new key" >&2; exit 1; }
	@mkdir -p private && chmod 700 private
	ssh-keygen -q -t ed25519 -C "boundgate release key $$(date +%Y-%m-%d)" -f private/release_signing_key
	cat private/release_signing_key.pub >> internal/update/release_keys
	cp internal/update/release_keys deploy/prod/release_keys
	@echo
	@echo "1. commit internal/update/release_keys and deploy/prod/release_keys"
	@echo "2. back up private/release_signing_key offline: whoever has it (and its passphrase) can ship updates to every node; who loses it cannot ship any (docs/RELEASES.md)"
	@echo "3. a second key as a reserve: run this again after moving the first one away, or list a FIDO2 key (ssh-keygen -t ed25519-sk) and use it with RELEASE_KEY=..."

# deploy/prod/update.sh against a stand-in for Gitea and docker
update-test:
	deploy/prod/update_test.sh

# deploy/prod/setup.sh (the curl | sh installer) with answers from a file
setup-test:
	deploy/prod/setup_test.sh

# deploy/release/tag-latest.sh against a registry in a container
tag-latest-test:
	deploy/release/tag-latest_test.sh

# The Secure Enclave bridge of a macOS node (key_kind secure-enclave / auto),
# for installs without the app (deploy/macos/install.sh). Swift, so it builds
# on the Mac and not in the box; the app bundle gets its own copy from mac-app.
mac-sekey:
	swift build --package-path apps/macos -c release --product boundgate-sekey
	@mkdir -p bin/darwin_$(GOARCH)
	cp "$$(swift build --package-path apps/macos -c release --show-bin-path)/boundgate-sekey" bin/darwin_$(GOARCH)/

# The one image every deployment pulls (deploy/prod, docs/DEPLOY.md). Binaries
# come from build-linux (Go in the box, cooldown-checked); the Dockerfile only
# adds ip/nft/CA roots. `image` builds for this machine's architecture into the
# local Docker; `image-push` builds amd64+arm64 and pushes them as one tag.
# Colima has no buildx plugin, so buildx runs from the docker:cli image
# against the VM's socket (builder "boundgate", a docker-container driver
# with the VM's binfmt for the foreign architecture). Pushing needs a
# `docker login gitlab.net407.com` on this Mac first (token with package:write).
IMAGE ?= gitlab.net407.com/sbh/boundgate
IMAGE_TAG ?= latest
PLATFORMS ?= linux/amd64,linux/arm64
REVISION := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILDX = docker run --rm -e DOCKER_HOST=unix:///var/run/docker.sock \
  -v /var/run/docker.sock:/var/run/docker.sock -v boundgate-buildx:/root/.docker/buildx \
  -v "$(HOME)/.docker/config.json:/root/.docker/config.json:ro" -v "$(CURDIR)":/work -w /work docker:cli buildx

image: build-linux
	docker build --build-arg TARGETARCH=$(GOARCH) --build-arg REVISION=$(REVISION) -t boundgate:local -f deploy/Dockerfile .

image-push:
	@for a in $$(echo "$(PLATFORMS)" | tr ',' ' ' | sed 's#linux/##g'); do $(MAKE) -o web build-linux GOARCH=$$a || exit 1; done
	@$(BUILDX) inspect boundgate >/dev/null 2>&1 || $(BUILDX) create --name boundgate --driver docker-container >/dev/null
	$(BUILDX) build --builder boundgate --platform $(PLATFORMS) --build-arg REVISION=$(REVISION) \
	  -t $(IMAGE):$(IMAGE_TAG) -t $(IMAGE):sha-$(REVISION) -f deploy/Dockerfile --push .

# The all-in-one kit end to end in the local Docker VM (docs/DEPLOY.md)
rehearsal: image
	deploy/prod/rehearsal.sh

test-race:
	box env CGO_ENABLED=1 go test -race -count=1 ./...

vet:
	box go vet ./...

fuzz:
	box go test -run=^$$ -fuzz=FuzzParse -fuzztime=30s ./internal/netparse
	box go test -run=^$$ -fuzz=FuzzParseSSHSIG -fuzztime=20s ./internal/binding
	box go test -run=^$$ -fuzz=FuzzParseBinding -fuzztime=20s ./internal/binding
	box go test -run=^$$ -fuzz=FuzzClientHelloSNI -fuzztime=20s ./internal/netparse
	box go test -run=^$$ -fuzz=FuzzDNSQueryName -fuzztime=20s ./internal/netparse
	box go test -run=^$$ -fuzz=FuzzTCPReset -fuzztime=20s ./internal/netparse

cooldown:
	box gocooldown check

compose-up: build-linux
	mkdir -p $(foreach s,control hub1 hub2 node-a node-r node-t node-m,deploy/compose/state/$(s) deploy/compose/logs/$(s))
	GOARCH=$(GOARCH) $(COMPOSE) up -d --build

compose-down:
	$(COMPOSE) down

compose-logs:
	$(COMPOSE) logs -f

setup-dev:
	deploy/compose/setup-dev.sh

e2e: compose-up
	deploy/compose/e2e.sh

clean:
	rm -rf bin
