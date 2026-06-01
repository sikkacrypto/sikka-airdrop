FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o airdrop . && go build -o nostr-airdrop ./cmd/nostr-airdrop

# ─────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/airdrop .
COPY --from=builder /app/nostr-airdrop .

# SQLite DB is stored in a mounted volume at /data
RUN mkdir -p /data

CMD ["./airdrop"]
