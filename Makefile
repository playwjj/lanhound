.PHONY: build web test vet run demo docker

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o lanhound ./cmd/lanhound

# Rebuild the embedded Vue front end (internal/web/dist).
web:
	cd web && npm ci && npm run build

test:
	go test ./...

vet:
	go vet ./... && GOOS=linux go vet ./...

# Run the watchdog on this machine's LAN (Linux; needs CAP_NET_RAW).
run: build
	sudo setcap cap_net_raw+ep ./lanhound && ./lanhound

# Try the UI anywhere with a simulated network.
demo: build
	./lanhound -demo -data ./data

docker:
	docker build --build-arg VERSION=$(VERSION) -t lanhound:$(VERSION) .
