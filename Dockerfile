FROM golang:1.27-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /lanhound ./cmd/lanhound

FROM scratch
COPY --from=build /lanhound /lanhound
ENTRYPOINT ["/lanhound"]
# Run with host networking and the one capability ARP needs:
#   docker run --rm --network host --cap-add=NET_RAW ghcr.io/playwjj/lanhound
