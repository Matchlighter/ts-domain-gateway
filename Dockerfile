FROM golang:1.26.6-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /domain-gateway ./cmd/domain-gateway

FROM alpine:3.22

COPY --from=build /domain-gateway /usr/local/bin/domain-gateway
ENTRYPOINT ["/usr/local/bin/domain-gateway"]
