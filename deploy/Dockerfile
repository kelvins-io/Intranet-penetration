# Multi-stage build for private deployment
FROM golang:1.24-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server ./cmd/server \
 && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/agent ./cmd/agent

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -H -u 10001 app
WORKDIR /app
COPY --from=build /out/server /out/agent /app/
COPY configs/server.yaml /app/configs/server.yaml
COPY configs/agent.yaml /app/configs/agent.yaml
USER app
EXPOSE 7700/tcp 7700/udp 8088 8443
ENTRYPOINT ["/app/server"]
CMD ["-config", "/app/configs/server.yaml"]
