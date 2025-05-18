FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o orchestrator ./cmd/orchestrator

FROM scratch

WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /app/orchestrator .

EXPOSE 8080
EXPOSE 50051

ENTRYPOINT ["./orchestrator"]