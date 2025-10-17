# Fleet Server

[![Build status](https://badge.buildkite.com/e97572322f4d22804d550aa300c7d4cfe807f3463c999e8c8f.svg?branch=main)](https://buildkite.com/elastic/fleet-server)

Fleet server is the control server to manage a fleet of [elastic-agents](https://github.com/elastic/elastic-agent).

Please refer to the [official documentation](https://www.elastic.co/guide/en/fleet/current/index.html) for more details.
For production deployments the fleet-server is supervised and bootstrapped by an elastic-agent.

## Quick Start

For more detailed instructions see the [Developer's Guide](./docs/developers-guide.md).

### Requirements

- Golang see [.go-version](./go-version) file for the current supported version.
- [mage](https://magefile.org/), may be installed with the `make mage` shortcut.

### Elasticsearch + Kibana

An Elasticsearch instance is needed in order to run fleet-server.
The following environment variables will need to be set with values from Elasticsearch/Kibana in order to run fleet-server:

- `ELASTICSEARCH_HOSTS` - The `schema://host:port` for Elasticsearch.
- `ELASTICSEARCH_CA_TRUSTED_FINGERPRINT` - The CA fingerprint for Elasticsearch.
- `ELASTICSEARCH_SERVICE_TOKEN` - The fleet-server service token.
- `FLEET_SERVER_POLICY_ID` - The fleet policy with the fleet-server integration.

For instructions/options on how to run the Elastic stack please refer to the [Developer's Guide](./docs/developers-guide.md).

### Build and run

To build the fleet-server binary to run locally use:

```bash
mage build:local # Use SNAPSHOT=true if targetting a SNAPSHOT build.
```

In order to run the fleet-server instance run:

```bash
./bin/fleet-server -c fleet-server.yml
```

Fleet-server should run on port `8220` an can be checked with:

```bash
curl -XGET -v http://localhost:8220/api/status
```

Please note that when running a stand-alone fleet-server instance, it will not appear in Kibana's agents view and another (agent-enrolled) instance may be required in order to the the UI to function as expected.
Please refer to the [Developer's Guide](./docs/developers-guide.md) for more details.
