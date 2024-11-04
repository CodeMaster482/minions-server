FROM golang:1.23.2-alpine3.20 AS builder

WORKDIR /app

COPY ../../. ./

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o minions-server ./services/gateway/cmd

FROM alpine:3.20

WORKDIR /app

COPY --from=builder /app/minions-server .

EXPOSE 8080

CMD ["./minions-server", "-c", "/app/config.yaml"]
