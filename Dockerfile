FROM golang:1.18.1-alpine as builder
WORKDIR /app
COPY . ./
RUN apk update && apk add gcc musl-dev
RUN CGO_ENABLED=1 GOOS=linux go build -o tcp-event prog/tcp_state/main.go prog/tcp_state/bpf_bpfel.go

FROM alpine:3.15.4
RUN apk --no-cache add ca-certificates

COPY --chown=0:0 --from=builder /app/tcp-event ./bin/
ENTRYPOINT ["tcp-event"]

