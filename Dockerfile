FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o odyssey-shield .

# ── runtime image ─────────────────────────────────────────────────
FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/odyssey-shield .
COPY config.yaml .

CMD ["./odyssey-shield"]
