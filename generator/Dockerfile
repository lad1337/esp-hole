## Builder: compile a static binary.
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/generator .

## Runtime: scratch + CA certs (sources are fetched over https).
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/generator /generator
VOLUME /data
EXPOSE 8080
EXPOSE 8094/udp
ENTRYPOINT ["/generator", "-config", "/config.json"]
