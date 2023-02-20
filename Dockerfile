ARG GO_VERSION
FROM golang:${GO_VERSION}-buster AS builder

WORKDIR /usr/src/fleet-server

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

ARG GCFLAGS=""
ARG LDFLAGS=""
ARG TAGS=""
RUN go build -tags="${TAGS}" -o /usr/bin/fleet-server -gcflags="${GCFLAGS}" -ldflags="${LCFLAGS}" .

FROM ubuntu:20.04

COPY fleet-server.yml /etc/fleet-server.yml
COPY --from=builder /usr/bin/fleet-server /usr/bin/fleet-server

CMD /usr/bin/fleet-server -c /etc/fleet-server.yml
