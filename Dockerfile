ARG GO_VERSION
FROM golang:${GO_VERSION}-buster AS builder

WORKDIR /usr/src/fleet-server

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

ARG GCFLAGS=""
ARG LDFLAGS=""
ARG DEV=""
RUN GCFLAGS="${GCFLAGS}" LDFLAGS="${LDFLAGS}" DEV="${DEV}" make release-linux/amd64

FROM ubuntu:20.04
ARG VERSION

COPY fleet-server.yml /etc/fleet-server.yml
COPY --from=builder /usr/src/fleet-server/build/binaries/fleet-server-${VERSION}-linux-x86_64/fleet-server /usr/bin/fleet-server

CMD /usr/bin/fleet-server -c /etc/fleet-server.yml
