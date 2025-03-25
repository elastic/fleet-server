# Docker Images

For production environments please use the elastic-agent image as described in our [documentation](https://www.elastic.co/guide/en/fleet/current/elastic-agent-container.html).

## Dockerfile

The [Dockerfile](../Dockerfile) contained with this project produces a stand-alone fleet-server image that is only supported for development purposes.

## Dockerfile.build

The [Dockerfile.build](../Dockerfile.build) contained with this project is used to produce release artifacts.

### Minimum MacOSX Version

The [golang-crossbuild](https://github.com/elastic/golang-crossbuild) image is used as the base for the [Dockerfile.build](#dockerfilebuild) container.
The `golang-crossbuild:1.16.X-darwin-debian11` images expects the minimum MacOSX version to be 10.14+.
