# Version Compatibility and upgrades

Fleet-server communicates with Elasticsearch. Elasticsearch must be on the same version or newer.
Fleet server is always on the exact same version as the Elastic Agent running fleet-server.
Any Elastic Agent enrolling into a fleet-server must be the same version or older.
For Kibana it is assumed it is on the same version as Elasticsearch. With this the compatibility looks as following:

```
Elastic Agent <= Elastic Agent with fleet-server <= Elasticsearch / Kibana
```

There might be differences on the bugfix version.

For upgrades Elasticsearch/Kibana must be upgraded first, then the Elastic Agent with fleet-server followed by any other Elastic Agents.
