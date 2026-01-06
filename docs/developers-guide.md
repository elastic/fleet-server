# Developers Guide

The following are notes to help developers onboarding to the project to quickly get running.
These notes might change at any time.

## Developing Fleet Server and Kibana at the same time

When developing features for Fleet, it may become necessary to run both Fleet Server and Kibana from source in order to implement features end-to-end.
To faciliate this, we've created a separate guide hosted [here](https://github.com/elastic/kibana/blob/main/x-pack/platform/plugins/shared/fleet/dev_docs/local_setup/developing_kibana_and_fleet_server.md).

## Mage usage

The fleet-server project uses [mage](https://magefile.org) as the build system.
After it is installed, targets can be shown by running `mage -l`.
To get help for a target run `mage -h TARGET`.

## Development build

To compile the fleet-server in development mode set the env var `DEV=true`.
When compiled in development mode the fleet-server will support debugging.
i.e.:

```shell
SNAPSHOT=true DEV=true PLATFORMS=darwin/amd64 mage release
```

Change `PLATFORMS` to `OS/ARCH` for your platform if it differs.
Run `mage platforms` to check out the possible values.

The `SNAPSHOT` flag sets the snapshot version flag and relaxes client version checks.
When `SNAPSHOT` is set we allow clients of the next version to communicate with fleet-server.
For example, if fleet-server is running version `8.11.0` on a `SNAPSHOT` build, clients can communiate with versions up to `8.12.0`.

### Development Docker build

You can build a fleet-server docker image with `mage docker:image`.
This image includes the default `fleet-server.yml` configuration file and can be customized with the available environment variables.

This image includes only `fleet-server` and is intended for stand alone mode, see the section about stand alone Fleet Server to know more.

You can run this image with the included configuration file with the following command:

```
docker run -it --rm \
  -e ELASTICSEARCH_HOSTS="https://elasticsearch:9200" \
  -e ELASTICSEARCH_SERVICE_TOKEN="someservicetoken" \
  -e ELASTICSEARCH_CA_TRUSTED_FINGERPRINT="somefingerprint" \
  docker.elastic.co/fleet-server/fleet-server:8.8.0
```

You can replace the included configuration by mounting your configuration file as a volume in `/etc/fleet-server.yml`.

```
docker run -it --rm \
  -e ELASTICSEARCH_HOSTS="https://elasticsearch:9200" \
  -e ELASTICSEARCH_SERVICE_TOKEN="someservicetoken" \
  -e ELASTICSEARCH_CA_TRUSTED_FINGERPRINT="somefingerprint" \
  -v "/path/to/your/fleet-server.yml:/etc/fleet-server.yml:ro" \
  docker.elastic.co/fleet-server/fleet-server:8.8.0
```

## Tests and benchmarks

When developing new features as you write code you would want to make sure your changes are not breaking any pre-existing functionality.
For this reason as you make changes you might want to run a subset of tests or the full tests before you create a pull request.

### Running go tests

To execute the full unit tests from your local environment you can do the following

```bash
mage test:unit
```

This target will execute the go unit tests and should normally pass without an issue.

To run tests in a package or a function, run like this:

```
go test -v ./internal/pkg/checkin -run TestBulkSimple
```

#### Integration Tests

Integration tests can be ran with:

```bash
mage test:integration
```

#### E2E Tests

All E2E tests are located in `testing/e2e`.

To execute them run:

```bash
mage test:e2e
```

Refer to the [e2e README](../testing/e2e/README.md) for information on how to write new tests.

### Benchmarks

It's a good practice before you start your changes to establish the current baseline of the benchmarks in your machine.
To establish the baseline benchmark report you can follow the following workflow.

**Establish a baseline**

```bash
BENCH_BASE=base.out mage test:benchmark
```

This will execute all the go benchmark test and write the output into the file build/base.out.
If you omit the `BENCH_BASE` variable it will automatically select the name `build/benchmark-{git_head_sha1}.out`.

**Re-running benchmark after changes**

After applying your changes into the code you can reuse the same command but with different output file.

```bash
BENCH_BASE=next.out mage test:benchmark
```

At this point you can compare the 2 reports using benchstat.

**Comparing the 2 results**

```bash
BENCH_BASE=base.out BENCH_NEXT=next.out mage test:benchstat
```

And this will print the difference between the baseline and next results.

You can read more on the [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) official site.

There are some additional parameters that you can use with the `benchmark` target.

- `BENCHMARK_FILTER`: you can define the test filter so that you only run a subset of tests (Default: Bench, only run the test BenchmarkXXXX and not unit tests)
- `BENCHMARK_ARGS`: you can define the benchmark args, such as `-count`, or other options such as `-benchmem` with this variable. The default is `-count=10 -benchtime=3s -benchmem`.

## IDE config

When using the gopls language server you may run into the following errors in the `testing` package:

```bash
error while importing github.com/elastic/fleet-server/testing/e2e/scaffold: build constraints exclude all Go files in  <path to fleet-server>/fleet-server/testing/e2e/scaffold
```

```bash
/<path to fleet-server>/fleet-server/testing/e2e/agent_install_test.go.
   This file may be excluded due to its build tags; try adding "-tags=<build tag>" to your gopls "buildFlags" configuration
   See the documentation for more information on working with build tags:
   https://github.com/golang/tools/blob/master/gopls/doc/settings.md#buildflags-string
```

In order to resolve the first issue you can add a `go.work` file to the root of this repo.
Copy and paste the following into `go.work`:

```go
go 1.21

use (
  .
  ./testing
  ./pkg/api
)

```

Solution for the second error depends on the ide and the package manager you are using.

### neovim

#### lazyvim package manager

##### nvim-lspconfig plugin

Add the following to your config files

```lua
{
  "neovim/nvim-lspconfig",
  opts = {
    servers = {
      gopls = {
        settings = {
          gopls = {
            buildFlags = { "-tags=e2e integration cloude2e" },
          },
        },
      },
    },
  },
}
```

After these changes if you are still running into issues with code suggestions, autocomplete, you may have to clear your go mod cache and restart your lsp clients.

Run the following command to clear your go mod cache:

```bash
go clean -modcache
```

Restart your vim session and run the following command to restart your lspclients:

```vim
:LspRestart
```

## Changelog

The changelog for fleet-server is generated and maintained using the [elastic-agent-changelog-tool](https://github.com/elastic/elastic-agent-changelog-tool).
Read the [installation](https://github.com/elastic/elastic-agent-changelog-tool/blob/main/docs/install.md) and [usage](https://github.com/elastic/elastic-agent-changelog-tool/blob/main/docs/usage.md#im-a-developer) instructions to get started.

The changelog tool produces fragment files that are consolidated to generate a changelog for each release.
Each PR containing a change with user impact (new feature, bug fix, etc.) must contain a changelog fragment describing the change.

A simple example of a changelog fragment is below for reference:

```yaml
kind: feature
summary: Accept raw errors as a fallback to detailed error type
pr: https://github.com/elastic/fleet-server/pull/2079
issue: https://github.com/elastic/elastic-agent/issues/931
```

## Vagrant

A Vagrantfile is provided to get an environment capable of developing and testing fleet-server.
In order to provision the vagrant box run:

```shell
vagrant plugin install vagrant-docker-compose
vagrant up
```

The folder above the repo's root is mounted at `/vagrant` in the VM.

## Multipass

A multipass target is provided to provision a multipass VM in order to develop and test fleet-server. To provision the VM run:

```bash
mage multipass
```

The folder above the repo's root is mounted at `~/git` in the VM.

## Running a local stack for development

Fleet-server can be ran locally in stand-alone mode alongside Elasticsearch and Kibana for development/testing.

Start by following the instructions to create a [development build](#development-build).

### ES and Kibana from SNAPSHOTS API on host

In order to run a development/snapshot fleet-server binary the corresponding SNAPSHOT builds of Elasticsearch and Kibana should be used:
The artifacts can be found with the artrifacts API, for example here's the [URL for 8.7-SNAPSHOT](https://artifacts-api.elastic.co/v1/search/8.7-SNAPSHOT) artifacts.

The request will result in a JSON blob that descibes all artifacts.
You will need to gather the URLs for Elasticsearch and Kibana that match your distribution, for example `linux/amd64`.

TODO: parse the JSON to get the URL

```shell
wget https://snapshots.elastic.co/8.7.0-19f30181/downloads/elasticsearch/elasticsearch-8.7.0-SNAPSHOT-linux-x86_64.tar.gz
wget https://snapshots.elastic.co/8.7.0-19f30181/downloads/kibana/kibana-8.7.0-SNAPSHOT-linux-x86_64.tar.gz
```

Generally you will need to unarchive and run the binaries:

```shell
tar -xzf elasticsearch-8.7.0-SNAPSHOT-linux-x86_64.tar.gz
cd elasticsearch-8.7.0-SNAPSHOT
# elasticsearch.yml can be edited if required
./bin/elasticsearch
```

The elasticsearch output will output the `elastic` user's password and a Kibana configuration string.

```shell
tar -xzf kibana-8.7.0-SNAPSHOT-linux-x86_64.tar.gz
cd kibana-8.7.0-SNAPSHOT
# kibana.yml can be edited if required
./bin/kibana
```

The kibana output will show a URL that will need to be visted in order to configure Kibana with the string elasticsearch provides.

More instructions for setup can be found in the [Elastic Stack Installation Guide](https://www.elastic.co/guide/en/elastic-stack/current/installing-elastic-stack.html).

#### Elasticsearch configuration

Elasticsearch configuration generally does not need to be changed when running a single-instance cluster for local testing.
See our [integration docker-compose.yml](../dev-tools/integration/docker-compose.yml) for an example of what is used for our testing configuration.

#### Kibana configuration

Custom Kibana configuration can be used to preload fleet with integrations and policies (by using the `xpack.fleet,packages` and `xpack.fleet.agentPolicies` attributes).
It can also be used to set fleet-settings such as the fleet-server hosts (`xpack.fleet.agents.fleet_server.hosts`) and outputs (`xpack.fleet`).
Please see our e2e tests [kibana.yml configuration](../dev-tools/e2e/kibana.yml) for a complete example.

Note that our tests run the Elasticsearch container on a Docker network where the host is called `elasticsearch`, the and the fleet-server container is called `fleet-server`.

### fleet-server stand alone

Fleet in Kibana requires a managed fleet-server (generally the one you enroll with the elastic-agent instructions).
To disable this requirement for a local fleet-server instance use:
`xpack.fleet.enableExperimental: ['fleetServerStandalone']` (available since `v8.8.0`).
This is only supported internally and is not intended for end-users at this time.

#### fleet-server configuration

Access the Fleet UI on Kibana and generate a fleet-server policy.
Set the following env vars with the information from Kibana:

- `ELASTICSEARCH_CA_TRUSTED_FINGERPRINT`
- `ELASTICSEARCH_SERVICE_TOKEN`
- `FLEET_SERVER_POLICY_ID`
  or edit `fleet-server.yml` to include these details directly.

Note the `fleet-server.reference.yml` contains a full configuration reference.

#### fleet-server certificates

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

### fleet-server+agent in a VM

A fleet-server managed by elastic-agent can also be built and ran in a VM.
The IP of the provided Vagrant machine is `192.168.56.43`.
The IP of the Multipass VM can easily be collected with `multipass list`.
The source files are mounted at `/vagrant` in the Vagrant machine and at `~/git` in the Multipass instance.

```bash
vagrant up
vagrant ssh
```

or

```bash
mage multipass
multipass shell fleet-server-dev
```

#### Build the elastic-agent

Once in a VM, and assuming that the repos are correctly mounted in `$SOURCE`.
Build the agent by running:

```shell
cd $SOURCE/elastic-agent
SNAPSHOT=true EXTERNAL=true PLATFORMS="linux/amd64" PACKAGES="tar.gz" mage -v dev:package # adjust PLATFORMS and PACKAGES to your system and needs.
```

For detailed instructions, check the [Elastic-Agent](https://github.com/elastic/elastic-agent) repo.

#### Run the elastic-agent+fleet-server in Vagrant

Copy and unpack the elastic-agent `.tar.gz` file and replace the `fleet-server` binary in `elastic-agent-8.Y.Z-SNAPSHOT-OS-ARCH/data/elastic-agent-*/components/` with the snapshot built from the fleet-server repo.

Then go to `Kibana > Managment > Fleet` and follow the instructions there.

Use `https://$IP:8220` as fleet-server host, where `$IP` is the VM's IP address.

##### tl;dr/example:

```shell
cp /vagrant/elastic-agent/build/distributions/elastic-agent-8.7.0-SNAPSHOT-linux-x86_64.tar.gz* ./
tar -xzf elastic-agent-8.7.0-SNAPSHOT-linux-x86_64.tar.gz
cd elastic-agent-8.7.0-SNAPSHOT-linux-x86_64
cp build/binaries/fleet-server-8.7.0-SNAPSHOT-linux-x86_64/fleet-server ./data/elastic-agent-494b79/components/
./elastic-agent install ...
```

## Testing on cloud

Elastic employees can create an Elastic Cloud deployment with a locally built Fleet Server.

To deploy it you can use the following commands:

```bash
EC_API_KEY=yourapikey make -C dev-tools/cloud cloud-deploy
```

And then to clean the deployment

```bash
EC_API_KEY=yourapikey make -C dev-tools/cloud cloud-clean
```

For more advanced scenario you can build a custom docker image that you could use in your own terraform.

```
make -C dev-tools/cloud build-and-push-cloud-image
```

## OpAMP

This section describes how to connect a OpenTelemetry Collector instance to Fleet Server over OpAMP.

1. Create a deployment in Elastic Cloud.  Integrations Server is not needed as we will instead be
   using the Fleet Server instance built from this repository so it can "speak" OpAMP to the OpenTelemetry
   Collector.
2. Create an Elasticsearch service account token using Kibana > Dev Tools > Console.
   ```
   POST /_security/service/elastic/fleet-server/credential/token/opamp
   ```
3. Create a `fleet-server.dev.yml` configuration file as described in https://github.com/elastic/kibana/blob/main/x-pack/platform/plugins/shared/fleet/dev_docs/local_setup/developing_kibana_and_fleet_server.md.
4. Build the Fleet Server binary for your platform.
   ```
   PLATFORMS=darwin/arm64 mage build:binary
   ```
5. Run the Fleet Server binary with the above configuration.
   ```
   ./build/binaries/fleet-server-9.4.0-darwin-aarch64/fleet-server -c fleet-server.dev.yml
   ```
6. Create a new policy in Fleet. Copy the enrollment token for that policy.
7. Create OpenTelemetry Collector configuration for connecting to the Fleet Server instance and save it as `otel-opamp.yaml`.
   ```yaml
   receivers:
     otlp:
       protocols:
         grpc:
           endpoint: 0.0.0.0:4317

   exporters:
     debug:
       verbosity: detailed

   extensions:
     opamp:
       server:
         http:
           endpoint: http://localhost:8220/v1/opamp
           tls:
             insecure: true
           headers:
             Authorization: ApiKey ${env:FLEET_ENROLLMENT_TOKEN}
       instance_uid: "019b8d7a-2da8-7657-b52d-492a9de33319"

   service:
     pipelines:
       logs:
         receivers: [otlp]
         exporters: [debug]
         extensions: [opamp]
   ```
7. Download and extract an OpenTelemetry Collector Contrib release for your platform from https://github.com/open-telemetry/opentelemetry-collector-releases/releases
8. Run the OpenTelemetry Collector with the above configuration.
   ```
   FLEET_ENROLLMENT_TOKEN=<enrollment token> ./otelcol-contrib --config ./otel-opamp.yaml
   ```
