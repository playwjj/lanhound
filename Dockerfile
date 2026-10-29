# syntax=docker/dockerfile:1
# Multi-arch build: the front end and the Go cross-compile run on the
# build host's platform; only the final scratch image is per-target.
# BuildKit sets BUILDPLATFORM itself; the default only matters for the
# legacy builder (Docker without buildx), which leaves it empty. On an
# ARM host without buildx pass --build-arg BUILDPLATFORM=linux/arm64.
ARG BUILDPLATFORM=linux/amd64

FROM --platform=$BUILDPLATFORM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/internal/web/dist ./internal/web/dist
RUN GOARM=${TARGETVARIANT#v} CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /lanhound ./cmd/lanhound
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /lanhound /lanhound
ENV LANHOUND_DATA=/data
VOLUME /data
EXPOSE 8686
ENTRYPOINT ["/lanhound"]
# Host networking and the one capability ARP needs:
#   docker run -d --name lanhound --network host --cap-add=NET_RAW \
#     -v lanhound-data:/data passport888/lanhound   (or ghcr.io/playwjj/lanhound)
