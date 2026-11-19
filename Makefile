.DEFAULT_GOAL := help
SHELL := /bin/bash

# Caddy matches the fleet's frankenwp-base image and the klm/caddy Habitat package (central).
CADDY_VERSION      ?= 2.11.7
PROTOC_GEN_GO      ?= v1.36.9
MODULE             := github.com/honest-hosting/caddy-ingress-guard
# Central's plugin set (infrastructure/habitat/caddy/habitat/plan.sh) for ingress-tier spikes (S3)
CENTRAL_PLUGINS    ?= --with github.com/corazawaf/coraza-caddy/v2@v2.6.2 \
                      --with github.com/honest-hosting/caddy-consul@v0.0.18

help: ## Display this help screen
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

proto: ## Regenerate bundle/bundlepb from proto/ (protoc-gen-go built into a temp dir)
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	GOBIN=$$tmp go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO) && \
	protoc --plugin=protoc-gen-go=$$tmp/protoc-gen-go --go_out=. --go_opt=module=$(MODULE) \
		-I proto proto/ingressguard/v1/bundle.proto

vet: ## go vet, with and without the panic-injection tag (root and the bundle module)
	go vet ./...
	go vet -tags ingressguard_panicinject ./...
	cd bundle && go vet ./...

test: ## Unit tests (root and the bundle module)
	go test ./...
	cd bundle && go test ./...

tool: ## Build the bundle tool to ./bin/ingress-guard-bundle (linux/amd64)
	GOOS=linux GOARCH=amd64 go build -o bin/ingress-guard-bundle ./cmd/ingress-guard-bundle

caddy: ## Build Caddy + this module to ./bin/caddy (linux/amd64)
	GOOS=linux GOARCH=amd64 xcaddy build v$(CADDY_VERSION) --output bin/caddy --with $(MODULE)=. --with $(MODULE)/bundle=./bundle

caddy-panic: ## Build Caddy + this module with S2 panic injection to ./bin/caddy-panic
	GOOS=linux GOARCH=amd64 XCADDY_GO_BUILD_FLAGS="-tags=ingressguard_panicinject" \
		xcaddy build v$(CADDY_VERSION) --output bin/caddy-panic --with $(MODULE)=. --with $(MODULE)/bundle=./bundle

caddy-race: ## Build Caddy + this module with the race detector to ./bin/caddy-race
	GOOS=linux GOARCH=amd64 XCADDY_RACE_DETECTOR=1 \
		xcaddy build v$(CADDY_VERSION) --output bin/caddy-race --with $(MODULE)=. --with $(MODULE)/bundle=./bundle

# Coraza 3.8.1 memoizes compiled patterns by default; memoize_builders is an obsolete tag that
# does nothing, so the comparison build turns it off instead.
caddy-nomemoize: ## Build with Coraza's pattern cache off (coraza.no_memoize) to ./bin/caddy-nomemoize (S2 run 2)
	GOOS=linux GOARCH=amd64 XCADDY_GO_BUILD_FLAGS="-tags=coraza.no_memoize" \
		xcaddy build v$(CADDY_VERSION) --output bin/caddy-nomemoize --with $(MODULE)=. --with $(MODULE)/bundle=./bundle

caddy-central: ## Build central's plugin set + this module to ./bin/caddy-central (S3)
	GOOS=linux GOARCH=amd64 xcaddy build v$(CADDY_VERSION) --output bin/caddy-central \
		$(CENTRAL_PLUGINS) --with $(MODULE)=. --with $(MODULE)/bundle=./bundle

clean: ## Remove ./bin
	rm -rf bin

.PHONY: help proto vet test tool caddy caddy-panic caddy-race caddy-nomemoize caddy-central clean
