[![Build Status](https://beats-ci.elastic.co/job/Ingest-manager/job/fleet-server/job/master/badge/icon)](https://beats-ci.elastic.co/job/Ingest-manager/job/fleet-server/job/master/)

# Fleet Server implementation

## Development

fleet-server is under development. The following are notes to help developers onboarding to the project to quickly get running. These notes might change at any time.

### Startup fleet-server

Currently to startup fleet-server, the Kibana encryption key is needed. There are two options for this.

Either the key `a...` is used in the kibana config as this is the default:

```
xpack.encryptedSavedObjects.encryptionKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
```

The alternative is to use `ES_SAVED_KEY` and pass it to fleet-server during setup with the value of the encryption key used in Kibana.


### Kibana

To be able to use Fleet Server with Kibana:
* you need to activate the feature flag `xpack.fleet.agents.fleetServerEnabled`.
* you need to configure the Kibana URL to use fleet server url (by default http://localhost:8000)
