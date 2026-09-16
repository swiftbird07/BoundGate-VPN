# All Go and Node commands run inside the `box` dev container (see docs/DEV.md).
GOARCH ?= $(shell uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
COMPOSE = docker compose -f deploy/compose/docker-compose.yml
BINS = boundgate-control boundgate-node boundgatectl boundgate-fakeidp

.PHONY: build-linux test test-race vet fuzz cooldown compose-up compose-down compose-logs setup-dev e2e clean

build-linux:
	@mkdir -p bin/linux_$(GOARCH)
	@for b in $(BINS); do \
	  echo "building $$b for linux/$(GOARCH)"; \
	  box env GOOS=linux GOARCH=$(GOARCH) go build -trimpath -o bin/linux_$(GOARCH)/$$b ./cmd/$$b || exit 1; \
	done

test:
	box go vet ./...
	box go test -count=1 ./...

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
	mkdir -p $(foreach s,control hub1 hub2 node-a node-r,deploy/compose/state/$(s) deploy/compose/logs/$(s))
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
