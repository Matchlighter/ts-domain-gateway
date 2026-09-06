FROM golang:1.27.0-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /domain-gateway ./cmd/domain-gateway

FROM python:3.13-slim
COPY --from=build /domain-gateway /usr/local/bin/domain-gateway
WORKDIR /e2e
