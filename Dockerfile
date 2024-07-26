ARG GO_VERSION
FROM --platform=${BUILDPLATFORM:-linux} golang:${GO_VERSION}-bullseye AS builder

WORKDIR /usr/src/fleet-server

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

ARG GCFLAGS=""
ARG LDFLAGS=""
ARG DEV=""
ARG TARGETPLATFORM

RUN GCFLAGS="${GCFLAGS}" LDFLAGS="${LDFLAGS}" DEV="${DEV}" make release-${TARGETPLATFORM}

FROM cgr.dev/chainguard/wolfi-base:latest
ARG VERSION
ARG TARGETOS
ARG TARGETARCH

RUN for iter in {1..10}; do \
        apk update && \
        apk add --no-cache shadow && \
        exit_code=0 && break || exit_code=$? && echo "apk error: retry $iter in 10s" && sleep 10; \
    done; \
    (exit $exit_code)

RUN groupadd --gid 1000 fleet-server && \
    useradd -M --uid 1000 --gid 1000 fleet-server

USER fleet-server

COPY --chown=fleet-server:fleet-server --chmod=644 fleet-server.yml /etc/fleet-server.yml
COPY --chown=fleet-server:fleet-server --chmod=755 --from=builder /usr/src/fleet-server/build/binaries/fleet-server-${VERSION}-${TARGETOS:-linux}-*/fleet-server /usr/bin/fleet-server

CMD /usr/bin/fleet-server -c /etc/fleet-server.yml
