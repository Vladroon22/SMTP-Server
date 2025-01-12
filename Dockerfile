FROM golang:1.23.4-alpine AS builder

WORKDIR /app

COPY . .

RUN go mod download

RUN go build -o smtp-server ./cmd/main.go

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/smtp-server .
COPY private_key.pem /app/private_key.pem

EXPOSE 2525

CMD ["./smtp-server"]