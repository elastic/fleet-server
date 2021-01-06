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

Currently there is some work to do to be able to run Kibana with Fleet Server and all the features are not yet supported, in the future, these workarounds will not be needed anymore.

* Start fleet-server before Kibana, to create the mappings in ES.
* Create and use a custom user as the `kibana_system` user
* Enable Fleet server usage with `xpack.fleet.agents.fleetServerEnabled: true`

```
POST /_security/role/kibana_fleet_system
{
   "cluster" : [
      "all"
    ],
    "indices" : [
      {
        "names" : [
          ".fleet*"
        ],
        "privileges" : [
          "all"
        ]
      }
    ]
}



POST /_security/user/kibana_fleet_system
{
  "password" : "changeme",
  "roles" : [ "kibana_system", "kibana_fleet_system" ]
}
```

Than configure your Kibana with
```
elasticsearch.username: 'kibana_fleet_system'
elasticsearch.password: 'changeme'
xpack.fleet.agents.fleetServerEnabled: true
```