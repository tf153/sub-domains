# --- build stage ---
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Cache deps first.
COPY go.mod go.sum ./
RUN go mod download

# Build the web server (static binary).
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server ./cmd/server

# --- runtime stage ---
FROM alpine:3.20

# CA certs are required for outbound HTTPS (crt.sh, RDAP, DoH, passive sources).
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app

COPY --from=builder /out/server /usr/local/bin/server

USER app
EXPOSE 8080

# App Platform injects PORT; the server reads it (default 8080).
ENTRYPOINT ["/usr/local/bin/server"]
