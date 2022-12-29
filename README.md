[![Build Status](https://fleet-ci.elastic.co/job/fleet-server/job/fleet-server-mbp/job/main/badge/icon)](https://fleet-ci.elastic.co/job/Ingest-manager/job/fleet-server/job/main/)

# Fleet Server

Fleet server is the control server to manage a fleet of [elastic-agents](https://github.com/elastic/elastic-agent).

For production deployments the fleet-server is supervised and bootstrapped by an elastic-agent.

To assist with development the fleet-server may run in a stand-alone mode.

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

### Development build

To compile the fleet-server in development mode set the env var `DEV=true`.
When compiled in development mode the fleet-server will support debugging and stand-alone execution.
i.e.:
```shell
SNAPSHOT=true DEV=true make release-darwin/amd64
GOOS=darwin GOARCH=amd64 go build -tags="dev" -gcflags="all=-N -l" -ldflags="-X main.Version=8.7.0 -X main.Commit=31668e0 -X main.BuildTime=2022-12-23T20:06:20Z" -buildmode=pie -o build/binaries/fleet-server-8.7.0-darwin-x86_64/fleet-server .
```

Change `release-darwin/amd64` to `release-YOUR_OS/platform`.
Run `make list-platforms` to check out the possible values.

The `SNAPSHOT` flag sets the snapshot version flag.

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

Access the Fleet UI on Kibana and generate a fleet-server policy.
Set the following env vars with the information from Kibana:
- `ELASTICSEARCH_CA_TRUSTED_FINGERPRINT`
- `ELASTICSEARCH_SERVICE_TOKEN`
- `FLEET_SERVER_POLICY_ID`

Then run the fleet-server:
```shell
./build/binaries/fleet-server-8.7.0-darwin-x86_64/fleet-server -c fleet-server.yml
```
By default the fleet-server will attempt to connect to Elasticsearch on `https://localhost:9200`, if this needs to be changed set it with `ELASTICSEARCH_HOSTS`
The fleet-server should appear as an agent with the ID `dev-fleet-server`.

#### fleet-server+agent on a Vagrant VM

The development Vagrant machine assumes the `elastic-agent`, `beats`, and `fleet-server` repos are in the same folder.
Thus, it mounts `../` to `/vagrant` on the Vagrant machine.
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
