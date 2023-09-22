FROM golang:1.20-alpine as builder
WORKDIR /app
COPY . ./
RUN apk update && apk add gcc musl-dev
ARG VERSION
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-X 'github.com/ddosify/alaz/datastore.tag=$VERSION'" -o alaz

FROM alpine:3.18.3
RUN apk --no-cache add ca-certificates

COPY --chown=0:0 --from=builder /app/alaz ./bin/
ENTRYPOINT ["alaz"]

