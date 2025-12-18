# OpAmp Support in Fleet Server

This document describes how to enable and configure OpAmp (Open Agent Management Protocol) support in Fleet Server for managing OpenTelemetry Collectors.

## Overview

Fleet Server can act as an OpAmp server, allowing OpenTelemetry Collectors to connect and report their status. The collectors' status, health, and configuration are stored in Elasticsearch.

## Prerequisites

Fleet Server will automatically create the `content-fleet-opamp-agents` index on first use. If the index already exists, it will be deleted and recreated with the correct mappings.

**Note:** The Fleet Server's Elasticsearch user must have permissions to create and delete indices.

## Configuration

### Enable OpAmp in Fleet Server

Add the following to your `fleet-server.yml` configuration:

```yaml
inputs:
  - type: fleet-server
    server:
      opamp:
        enabled: true
        path: "/v1/opamp"  # Optional, this is the default
```

Or set via environment variable:
```bash
FLEET_SERVER_OPAMP_ENABLED=true
```

### Configure OpenTelemetry Collector

Configure your OpenTelemetry Collector to connect to Fleet Server using the OpAmp extension:

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
    instance_uid: "01KCQBWBB5ES54Z8J9J2S4XB9B"
    capabilities:
      reports_effective_config: true
    server:
      http:
        endpoint: http://host.docker.internal:8220/v1/opamp
        tls:
          insecure: true

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
  extensions: [opamp]

```

## Data Stored

When a collector connects, the following information is stored in the `content-fleet-opamp-agents` index:

| Field | Description |
|-------|-------------|
| `@timestamp` | When the status was last updated |
| `opamp.agent.instance_uid` | Unique identifier for the collector instance |
| `opamp.status` | Current status: `online`, `healthy`, or `degraded` |
| `opamp.health.*` | Health information including component health |
| `opamp.capabilities` | List of OpAmp capabilities the agent supports |
| `opamp.effective_config` | The collector's current configuration |
| `opamp.sequence_num` | Message sequence number |
| `connection.last_seen` | When the collector last checked in |
| `connection.protocol` | Always `http` for OpAmp HTTP connections |
| `agent.*` | ECS-compatible agent information |
| `host.*` | ECS-compatible host information |

## Rate Limiting

OpAmp connections are rate-limited using the same mechanism as other Fleet Server endpoints. Default limits:

- Interval: 1ms
- Burst: 1000
- Max body size: 1MB

Configure via:
```yaml
inputs:
  - type: fleet-server
    server:
      limits:
        opamp_limit:
          interval: 1ms
          burst: 1000
          max_body_byte_size: 1048576
```

## Querying Connected Collectors

Query the `content-fleet-opamp-agents` index to see connected collectors:

```bash
curl -X GET "https://localhost:9200/content-fleet-opamp-agents/_search?pretty" \
  -H "Content-Type: application/json" \
  -u elastic:changeme \
  -d '{
    "query": {
      "term": { "opamp.status": "healthy" }
    }
  }'
```

## Index Management

Fleet Server automatically manages the `content-fleet-opamp-agents` index:

- On first OpAmp connection, the index is created with proper mappings
- If the index already exists with incompatible mappings, it is deleted and recreated
- This ensures the index always has the correct schema

### Manual Index Creation (Optional)

If you prefer to create the index manually before starting Fleet Server, use:

```
PUT /content-fleet-opamp-agents
{contents of internal/pkg/api/opamp_index_settings.json from the repository}
```