ARG GO_VERSION
ARG SUFFIX
FROM --platform=${BUILDPLATFORM:-linux} docker.elastic.co/beats-dev/golang-crossbuild:${GO_VERSION}-${SUFFIX} AS builder

WORKDIR /fleet-server

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify
RUN go install github.com/magefile/mage # Uses version from go.mod implicitly
ENV PATH="$PATH:/go/bin"
ENV MAGEFILE_CACHE=/fleet-server/build/.magefile

COPY . .

ARG GCFLAGS=""
ARG LDFLAGS=""
ARG DEV=""
ARG SNAPSHOT=""
ARG TARGETPLATFORM

RUN GCFLAGS="${GCFLAGS}" LDFLAGS="${LDFLAGS}" SNAPSHOT="${SNAPSHOT}" DEV="${DEV}" PLATFORMS="${TARGETPLATFORM}" mage build:release

FROM cgr.dev/chainguard/wolfi-base:latest
ARG VERSION

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
COPY --chown=fleet-server:fleet-server --chmod=555 --from=builder /fleet-server/build/binaries/fleet-server-${VERSION}-linux-*/fleet-server /usr/bin/fleet-server

CMD /usr/bin/fleet-server -c /etc/fleet-server.yml
