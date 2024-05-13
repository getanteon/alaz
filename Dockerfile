FROM golang:1.22.1-bullseye as builder
WORKDIR /app
COPY . ./
RUN apt update

ARG VERSION
ENV GOCACHE=/root/.cache/go-build
RUN go mod tidy -v
RUN --mount=type=cache,target="/root/.cache/go-build" GOOS=linux go build -ldflags="-X 'github.com/ddosify/alaz/datastore.tag=$VERSION'" -o alaz

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.3-1552
RUN microdnf update -y && microdnf install procps ca-certificates -y && microdnf clean all

COPY --chown=1001:0 --from=builder /app/alaz ./bin/
COPY --chown=1001:0 LICENSE /licenses/LICENSE

USER 1001
ENTRYPOINT ["alaz"]
