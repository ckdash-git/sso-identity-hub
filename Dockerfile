# ============================================================
# Stage 1: Builder
# ============================================================
FROM golang:1.22-alpine AS builder

# Install CA certificates and git (needed for private module fetches)
RUN apk add --no-cache ca-certificates git tzdata

WORKDIR /build

# Copy go.mod first. go.sum does not exist yet in this repository;
# it will be generated inside the builder by go mod tidy below.
COPY go.mod ./

# Copy all source so go mod tidy can resolve the full transitive import graph.
COPY . .

# Generate go.sum from the full dependency graph, then pre-download all
# modules into the build cache so the final go build has no network calls.
RUN go mod tidy && go mod download

# Build a statically-linked binary.
# CGO_ENABLED=0 guarantees a fully static binary that runs on scratch/distroless.
# -trimpath removes local path references from the binary.
# -ldflags "-s -w" strips debug symbols (reduces image size by ~30%).
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -trimpath \
    -ldflags="-s -w -extldflags '-static'" \
    -o /build/sso-server \
    ./cmd/server/main.go

# ============================================================
# Stage 2: Runtime
# ============================================================
FROM scratch

# Pull in CA certs and timezone data from the builder stage
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /build/sso-server /sso-server

# Copy database migration files
COPY --from=builder /build/migrations /migrations

# The /secrets directory is injected via a bind mount at runtime.
# Never bake secrets into the image.
VOLUME ["/secrets"]

# The application listens on 8080.
EXPOSE 8080

# Run as non-root uid 65532 (nobody equivalent in scratch images)
USER 65532:65532

ENTRYPOINT ["/sso-server"]
