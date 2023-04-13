[![Build Status](https://fleet-ci.elastic.co/job/fleet-server/job/fleet-server-mbp/job/main/badge/icon)](https://fleet-ci.elastic.co/job/Ingest-manager/job/fleet-server/job/main/)

# Fleet Server

Fleet server is the control server to manage a fleet of [elastic-agents](https://github.com/elastic/elastic-agent).

For production deployments the fleet-server is supervised and bootstrapped by an elastic-agent.

## Compatibility and upgrades

Fleet-server communicates with Elasticsearch. Elasticsearch must be on the same version or newer.
Fleet server is always on the exact same version as the Elastic Agent running fleet-server.
Any Elastic Agent enrolling into a fleet-server must be the same version or older.
For Kibana it is assumed it is on the same version as Elasticsearch. With this the compatibility looks as following:
```
Elastic Agent <= Elastic Agent with fleet-server <= Elasticsearch / Kibana
```

There might be differences on the bugfix version.

For upgrades Elasticsearch/Kibana must be upgraded first, then the Elastic Agent with fleet-server followed by any other Elastic Agents.

## MacOSX Version

The [golang-crossbuild](https://github.com/elastic/golang-crossbuild) produces images used for testing/building.
The `golang-crossbuild:1.16.X-darwin-debian10` images expects the minimum MacOSX version to be 10.14+.

## Development

The following are notes to help developers onboarding to the project to quickly get running. These notes might change at any time.

### Changelog

The changelog for fleet-server is generated and maintained using the [elastic-agent-changelog-tool](https://github.com/elastic/elastic-agent-changelog-tool).
Read the [installation](https://github.com/elastic/elastic-agent-changelog-tool/blob/main/docs/install.md) and [usage](https://github.com/elastic/elastic-agent-changelog-tool/blob/main/docs/usage.md#im-a-developer) instructions to get started.

The changelog tool produces fragement files that are consolidated to generate a changelog for each release
Each PR containing a change with user impact (new feature, bug fix, etc.) must contain a changelog fragement describing the change.

A simple example of a changelog fragment is below for reference:
```yaml
kind: feature
summary: Accept raw errors as a fallback to detailed error type
pr: https://github.com/elastic/fleet-server/pull/2079
issue: https://github.com/elastic/elastic-agent/issues/931
```

### Development build

To compile the fleet-server in development mode set the env var `DEV=true`.
When compiled in development mode the fleet-server will support debugging.
i.e.:
```shell
SNAPSHOT=true DEV=true make release-darwin/amd64
GOOS=darwin GOARCH=amd64 go build -tags="dev" -gcflags="all=-N -l" -ldflags="-X main.Version=8.7.0 -X main.Commit=31668e0 -X main.BuildTime=2022-12-23T20:06:20Z" -buildmode=pie -o build/binaries/fleet-server-8.7.0-darwin-x86_64/fleet-server .
```

Change `release-darwin/amd64` to `release-YOUR_OS/platform`.
Run `make list-platforms` to check out the possible values.

The `SNAPSHOT` flag sets the snapshot version flag.

### Docker build

You can build a fleet-server docker image with `make build-docker`. This image
includes the default `fleet-server.yml` configuration file and can be customized
with the available environment variables.

This image includes only `fleet-server` and is intended for stand alone mode, see
the section about stand alone Fleet Server to know more.

You can run this image with the included configuration file with the following
command:
```
docker run -it --rm \
  -e ELASTICSEARCH_HOSTS="https://elasticsearch:9200" \
  -e ELASTICSEARCH_SERVICE_TOKEN="someservicetoken" \
  -e ELASTICSEARCH_CA_TRUSTED_FINGERPRINT="somefingerprint" \
  docker.elastic.co/fleet-server/fleet-server:8.8.0
```

You can replace the included configuration by mounting your
configuration file as a volume in `/etc/fleet-server.yml`.
```
docker run -it --rm \
  -e ELASTICSEARCH_HOSTS="https://elasticsearch:9200" \
  -e ELASTICSEARCH_SERVICE_TOKEN="someservicetoken" \
  -e ELASTICSEARCH_CA_TRUSTED_FINGERPRINT="somefingerprint" \
  -v "/path/to/your/fleet-server.yml:/etc/fleet-server.yml:ro" \
  docker.elastic.co/fleet-server/fleet-server:8.8.0
```

### Running a development build

#### ES and Kibana from SNAPSHOTS API on host

Download SNAPSHOT builds for Elasticsearch and Kibana from the snapshots API:
Edit the version and OS/arch to suit your system, or [check the API](https://artifacts-api.elastic.co/v1/search/8.7-SNAPSHOT) (change the version if needed) if the ones below does not suit you.
 - 8.7.0-SNAPSHOT-linux-x86_64.tar.gz
 - 8.7.0-SNAPSHOT-darwin-aarch64.tar.gz
 - 8.7.0-SNAPSHOT-windows-x86_64.zip

TODO: parse the JSON to get the URL
```shell
wget https://snapshots.elastic.co/8.7.0-19f30181/downloads/elasticsearch/elasticsearch-8.7.0-SNAPSHOT-linux-x86_64.tar.gz
wget https://snapshots.elastic.co/8.7.0-19f30181/downloads/kibana/kibana-8.7.0-SNAPSHOT-linux-x86_64.tar.gz
```

Generally you will need to unarchive and run the binaries:

```shell
tar -xzf elasticsearch-8.7.0-SNAPSHOT-linux-x86_64.tar.gz
cd elasticsearch-8.7.0-SNAPSHOT
./bin/elasticsearch
```

The elasticsearch output will output the `elastic` user's password and a Kibana configuration string.

```shell
tar -xzf kibana-8.7.0-SNAPSHOT-linux-x86_64.tar.gz
cd kibana-8.7.0-SNAPSHOT
./bin/kibana
```

The kibana output will show a URL that will need to be visted in order to configure Kibana with the string elasticsearch provides.

More instructions for setup can be found in the [Elastic Stack Installation Guide](https://www.elastic.co/guide/en/elastic-stack/current/installing-elastic-stack.html).

#### fleet-server stand alone

Fleet UI requires a managed Fleet Server, to be able to use stand alone Fleet
server, you need to enroll a managed Fleet Server or disable this requirement.
You can disable this requirement since Kibana 8.8.0, starting it with
`xpack.fleet.enableExperimental: ['fleetServerStandalone']`. This is only
supported internally and is not intended for end-users at this time.

Access the Fleet UI on Kibana and generate a fleet-server policy.
Set the following env vars with the information from Kibana:
- `ELASTICSEARCH_CA_TRUSTED_FINGERPRINT`
- `ELASTICSEARCH_SERVICE_TOKEN`
- `FLEET_SERVER_POLICY_ID`

Create a self-signed TLS CA and cert+key for the fleet-server instance, you can use [elasticsearch-certutil](https://www.elastic.co/guide/en/elasticsearch/reference/current/certutil.html) for this:
```shell
# Create a CA
../elasticsearch/bin/elasticsearch-certutil ca --pem --out stack.zip
unzip stack.zip
# Create a cert+key
../elasticsearch/bin/elasticsearch-certutil cert --pem --ca-cert ca/ca.crt --ca-key ca/ca.key --ip $HOST_IP_ADDR --out cert.zip
unzip cert.zip
```

Ensure that `server.ssl.enabled: true` is set as well as the `server.ssl.certificate` and `server.ssl.key` attributes in `fleet-server.yml`

Then run the fleet-server:
```shell
./build/binaries/fleet-server-8.7.0-darwin-x86_64/fleet-server -c fleet-server.yml
```
By default the fleet-server will attempt to connect to Elasticsearch on `https://localhost:9200`, if this needs to be changed set it with `ELASTICSEARCH_HOSTS`
The fleet-server should appear as an agent with the ID `dev-fleet-server`.

Any additional agents will need the `ca/ca.crt` file to enroll (or will need to use the `--insecure` flag).

#### fleet-server+agent on a Vagrant VM

The development Vagrant machine assumes the `elastic-agent`, `beats`, and `fleet-server` repos are in the same folder.
Thus, it mounts `../` to `/vagrant` on the Vagrant machine. The vagrant machine IP address is `192.168.56.43`.
Use `https://192.168.56.43:8220` as fleet-server host.
```shell
vagrant up
vagrant ssh
```

##### Build the elastic-agent

Once in the Vagrant VM, and assuming that the repos are correctly mounted in `/vagrant`.
Build the agent by running:
```shell
cd /vagrant/elastic-agent
SNAPSHOT=true EXTERNAL=true PLATFORMS="linux/amd64" PACKAGES="tar.gz" mage -v dev:package # adjust PLATFORMS and PACKAGES to your system and needs.
```

For detailed instructions, check the [Elastic-Agent](https://github.com/elastic/elastic-agent) repo.

##### Run the elastic-agent+fleet-server in Vagrant

Copy and unpack the elastic-agent `.tar.gz` file and replace the `fleet-server` binary in `elastic-agent-8.Y.Z-SNAPSHOT-OS-ARCH/data/elastic-agent-*/components/` with the snapshot from the fleet-server repo.

Then go to `Kibana > Managment > Fleet` and follow the instructions there.

The vagrant machine IP address is `192.168.56.43`.
Use `https://192.168.56.43:8220` as fleet-server host.

##### tl;dr/example:

```shell
cp /vagrant/elastic-agent/build/distributions/elastic-agent-8.7.0-SNAPSHOT-linux-x86_64.tar.gz* ./
tar -xzf elastic-agent-8.7.0-SNAPSHOT-linux-x86_64.tar.gz
cd elastic-agent-8.7.0-SNAPSHOT-linux-x86_64
cp build/binaries/fleet-server-8.7.0-SNAPSHOT-linux-x86_64/fleet-server ./data/elastic-agent-494b79/components/
./elastic-agent install ...
```


### Running go test and benchmarks

When developing new features as you write code you would want to make sure your changes are not breaking any pre-existing
functionality. For this reason as you make changes you might want to run a subset of tests or the full tests before
you create a pull request.

#### Running go tests

To execute the full unit tests from your local environment you can do the following
```bash
make test-unit
```

This make target will execute the go unit tests and should normally pass without an issue.

#### Running go benchmark tests

It's a good practice before you start your changes to establish the current baseline of the benchmarks in your machine.
To establish the baseline benchmark report you can follow the following workflow

__Establish a baseline__
```bash
BENCH_BASE=base.out make benchmark
```

This will execute all the go benchmark test and write the output into the file build/base.out. If you omit the
`BENCH_BASE` variable it will automatically select the name `build/benchmark-{git_head_sha1}.out`.

__Re-running benchmark after changes__

After applying your changes into the code you can reuse the same command but with different output file.
```bash
BENCH_BASE=next.out make benchmark
```

At this point you can compare the 2 reports using benchstat.

__Comparing the 2 results__
```bash
BENCH_BASE=base.out BENCH_NEXT=next.out make benchstat
```

And this will print the difference between the baseline and next results.

You can read more on the [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) official site.

There are some additional parameters that you can use with the `benchmark` target.
- `BENCHMARK_FILTER`: you can define the test filter so that you only run a subset of tests (Default: Bench, only run
the test BenchmarkXXXX and not unit tests)
- `BENCHMARK_COUNT`: you can define the number of iterations go test will run. Having larger number helps
remove run-to-run variations (Default: 8)
