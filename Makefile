# All Go and Node commands run inside the `box` dev container (see docs/DEV.md).
GOARCH ?= $(shell uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
COMPOSE = docker compose -f deploy/compose/docker-compose.yml
BINS = boundgate-control boundgate-node boundgatectl boundgate-fakeidp boundgate-udpbridge

.PHONY: test-tpm web web-dev web-check web-test build-linux build-darwin test test-race vet fuzz cooldown compose-up compose-down compose-logs setup-dev e2e clean

# The admin SPA (web/) is built into internal/control/web/dist and embedded
# into boundgate-control; build-linux depends on it so the lab image has it.
web:
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

# policy builder: every generated rule parses back into the same model
web-test:
	box sh -c 'cd web && npm test --silent >/dev/null'

build-linux: web
	@mkdir -p bin/linux_$(GOARCH)
	@for b in $(BINS); do \
	  echo "building $$b for linux/$(GOARCH)"; \
	  box env GOOS=linux GOARCH=$(GOARCH) go build -trimpath -o bin/linux_$(GOARCH)/$$b ./cmd/$$b || exit 1; \
	done

# The macOS node (M5): cross-compiled in the box, run on the host with
# deploy/macos/dev.sh. The control plane is not built for macOS.
build-darwin:
	@mkdir -p bin/darwin_$(GOARCH)
	@for b in boundgate-node boundgatectl boundgate-udpbridge; do \
	  echo "building $$b for darwin/$(GOARCH)"; \
	  box env GOOS=darwin GOARCH=$(GOARCH) CGO_ENABLED=0 go build -trimpath -o bin/darwin_$(GOARCH)/$$b ./cmd/$$b || exit 1; \
	done

test: web-test
	box go vet ./...
	box go test -count=1 ./...

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
	mkdir -p $(foreach s,control hub1 hub2 node-a node-r node-t,deploy/compose/state/$(s) deploy/compose/logs/$(s))
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
