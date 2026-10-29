.PHONY: build test vet run

build:
	CGO_ENABLED=0 go build -trimpath -o lanhound ./cmd/lanhound

test:
	go test ./...

vet:
	go vet ./...

# A one-off scan of this machine's own LAN (needs CAP_NET_RAW).
run: build
	sudo setcap cap_net_raw+ep ./lanhound && ./lanhound
