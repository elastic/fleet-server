# syntax=docker/dockerfile:experimental

############################
# STEP 0 build environment
############################
# golang:1.15.2-alpine3.12
FROM golang@sha256:4d8abd16b03209b30b48f69a2e10347aacf7ce65d8f9f685e8c3e20a512234d9 as buildenv

# Install git + SSL ca certificates.
# Git is required for fetching the dependencies.
# Ca-certificates is required to call HTTPS endpoints.
RUN apk update && apk add --no-cache git openssh-client ca-certificates tzdata && update-ca-certificates

# download public key for github.com
RUN mkdir -p -m 0600 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts

# Create appuser
RUN adduser -D -g '' appuser

# Setup workdir in the build image
WORKDIR $GOPATH/src/fleet-server/

# Allow our private modules
ENV GOPRIVATE=github.com/elastic/*
RUN git config --global url."git@github.com:".insteadOf "https://github.com/"

COPY go.mod .
COPY go.sum .

# Download and validate packages, these will get cached as a layer so should only happen once.
RUN --mount=type=ssh go mod download -x
RUN --mount=type=ssh go mod verify

# Dupe the source code in the target
COPY . .

# Setup env
ENV CGO_ENABLED=0
ENV GOOS=linux

############################
# STEP 1 build executable binary
############################
from buildenv as builder

# Build the binary, use ldflags to minimize executable size
ARG LDFLAGS
RUN --mount=type=cache,target=/root/.cache/go-build go build -trimpath -ldflags="$LDFLAGS" -o /go/bin/fleet-server .

COPY ./fleet-server.yml /go/bin/fleet-server.yml


############################
# STEP 2 build a small image fleet
############################
FROM scratch as fleet

# Import from builder.
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd

# Copy our static executable
COPY --from=builder /go/bin/fleet-server /go/bin/fleet-server
COPY --from=builder /go/bin/fleet-server.yml /go/bin/fleet-server.yml

# Use an unprivileged user.
USER appuser

# Set the workdir so the fleet binary can find fleet-server.yml
WORKDIR "/go/bin/"

# Run the fleet binary.
ENTRYPOINT ["./fleet-server"]

############################
# STEP 2 rpmbuild
############################
FROM goreleaser/nfpm as rpmbuild

# Dupe out the artifacts we need
COPY . .

# Copy our static executables
COPY --from=builder /go/bin/fleet-server ./bin/fleet-server

env APP_VERSION=${VERSION}
env APP_RELEASE=${COMMIT}

RUN nfpm pkg --config ./dev-tools/rpm/nfpm.yaml --target out.rpm

############################
# STEP 5 rpm
############################
FROM scratch as rpm

ARG VERSION
ARG COMMIT
COPY --from=rpmbuild out.rpm ./fleet-${VERSION}-0.${COMMIT}.x86_64.rpm


