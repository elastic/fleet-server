[![Build Status](https://beats-ci.elastic.co/job/Ingest-manager/job/fleet-server/job/master/badge/icon)](https://beats-ci.elastic.co/job/Ingest-manager/job/fleet-server/job/master/)

# Fleet Server implementation

## Development

fleet-server is under development. The following are notes to help developers onboarding to the project to quickly get running. These notes might change at any time.

## Setup

To run and test fleet-server, a recent version of Elastic Agent and Kibana are needed. In the following Elastic Agent and Kibana are built from source. The fleet-server itself is not built from source but pulled from the latest snapshot build. It would be possible to also pull Elastic Agent or Kibana from the latest snapshot but the assumption that is made here that whoever is testing this, is likely developing either Elastic Agent or on the Kibana side.


### Kibana setup

The source code of Kibana must be checked out. After checkout, the following command must be run:

```
yarn kbn bootstrap
```

This will take a while the first time it is run. An error might be return in case not a valid node version is installed. Use nvm to install the correct version.

Next, Kibana and Elasticsearch must be started. On the Kibana side, an additional configuration flag is required. I personally put this into `config/kibana.dev.yml` in the Kibana repo as this file is ignored from git. The content to put in there is:

```
xpack.fleet.agents.fleetServerEnabled: true
```

This enables the fleet-server setup in Kibana. Now the following two commands must be run in parallel:

```
# Start ES
yarn es snapshot -E xpack.security.authc.api_key.enabled=true

# Start KB
yarn start --no-base-path
```

As soon as all is running, go to `http://localhost:5601`, enter `elastic/changeme` as credential and navigate to Fleet. Trigger the Fleet setup. As soon as this is completed, copy the `policy id` and `enrollment token` for the fleet-server policy. The policy id can be copied from the URL, the enrollment token can be found in the Enrollment Token list. 

Now Kibana is running and ready. The next step is to setup Elastic Agent.

## Beats repo

To build the Elastic Agent from source, check out the beats repository. Navigate to `x-pack/elastic-agent` and run the following command:

```
SNAPSHOT=true DEV=true PLATFORMS=darwin mage package
```

The above assumes you are running on OS X. Put the platform in you are running on. This speeds up packaging as it only builds it for your platform. As soon as this is completed (it might take a while for the first time) navigate to `build/distributions` and unpackage the `.tar.gz`. Navigate into the elastic-agent directory and start the Elastic Agent:

```
sudo ./elastic-agent -v
```

Currently a second command has to be run in parallel to setup fleet-server. Take the enrollment token and policy id you copied from Kibana and replace it in the command below:

```
sudo ./elastic-agent enroll --enrollment-token {enrollment-token} --fleet-server http://elastic:changeme@localhost:9200 --fleet-server-policy {fleet-server-policy-id}
```

This will start up fleet-server and the command should complete. After this, navigate to Kibana and check if the Elastic Agent with fleet-server shows up.



sudo ./elastic-agent -v
