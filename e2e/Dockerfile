FROM golang:1.27.0-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /domain-gateway ./cmd/domain-gateway

FROM python:3.13-slim
COPY --from=build /domain-gateway /usr/local/bin/domain-gateway
WORKDIR /e2e
