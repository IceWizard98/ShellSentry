# Multi-stage: build ssentry on Linux, then a slim runtime image that runs the
# integration harness (command interception + base rules). Build context = repo root.
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/ssentry ./cmd/ssentry

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ssentry /usr/local/bin/ssentry
COPY docker/mock_scorer.py docker/totp.py docker/harness.sh /harness/
RUN chmod +x /harness/harness.sh /usr/local/bin/ssentry
WORKDIR /work
ENTRYPOINT ["/harness/harness.sh"]
