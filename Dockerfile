FROM golang:1.26.1-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /barry ./main.go

FROM alpine:3.20

RUN apk add --no-cache ca-certificates git

COPY --from=builder /barry /barry

ENTRYPOINT ["/barry"]
