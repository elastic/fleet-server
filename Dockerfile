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

FROM ubuntu:20.04
ARG VERSION
ARG TARGETOS
ARG TARGETARCH

COPY fleet-server.yml /etc/fleet-server.yml
COPY --from=builder /usr/src/fleet-server/build/binaries/fleet-server-${VERSION}-${TARGETOS:-linux}-*/fleet-server /usr/bin/fleet-server

CMD /usr/bin/fleet-server -c /etc/fleet-server.yml
