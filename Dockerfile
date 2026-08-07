# syntax=docker/dockerfile:1
# NexusLink 服务端多阶段构建
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/nexuslink-server ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
ENV TZ=Asia/Shanghai
WORKDIR /app
COPY --from=builder /out/nexuslink-server /usr/local/bin/nexuslink-server
COPY docker/server.yaml /app/server.yaml
EXPOSE 7000 7001
VOLUME ["/data"]
CMD ["nexuslink-server", "-c", "/app/server.yaml"]
