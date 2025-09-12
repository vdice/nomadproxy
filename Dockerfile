# syntax=docker/dockerfile:1

FROM --platform=${BUILDPLATFORM} golang:1.25 as base

WORKDIR /usr/src/app

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY nomadproxy.go .

FROM --platform=${BUILDPLATFORM} base as build

RUN --mount=type=cache,target=/root/.cache/go-build \
  CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -v -o /usr/local/bin/nomadproxy ./nomadproxy.go

FROM --platform=${TARGETPLATFORM} scratch

WORKDIR /

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /usr/local/bin/nomadproxy /

LABEL org.opencontainers.image.source = "https://github.com/endocrimes/nomadproxy"

ENTRYPOINT ["/nomadproxy"]
