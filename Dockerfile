FROM golang:1.27 AS builder

WORKDIR /app

COPY go.mod ./
COPY . .

RUN go build -o security-scanner .

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/security-scanner .

ENTRYPOINT ["./security-scanner"]