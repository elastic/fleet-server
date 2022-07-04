// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

const testPolicy = `
{
   "id": "63f4e6d0-9626-11eb-b486-6de1529a4151",
   "revision": 33,
   "outputs": {
      "other": {
         "type": "elasticsearch",
         "hosts": [
            "https://5a8bb94bfbe0401a909e1496a9e884c2.us-central1.gcp.foundit.no:443"
         ],
         "fleet_server": {}
      },
      "remote_not_es": {
         "type": "logstash",
         "hosts": [
            "https://5a8bb94bfbe0401a909e1496a9e884c2.us-central1.gcp.foundit.no:443"
         ]
      }
   },
   "output_permissions": {
      "other": {
         "_fallback": {
            "cluster": [
               "monitor"
            ],
            "indices": [
               {
                  "names": [
                     "logs-*",
                     "metrics-*",
                     "traces-*",
                     ".logs-endpoint.diagnostic.collection-*"
                  ],
                  "privileges": [
                     "auto_configure",
                     "create_doc"
                  ]
               }
            ]
         }
      }
   },
   "agent": {
      "monitoring": {
         "enabled": true,
         "use_output": "remote_not_es",
         "logs": true,
         "metrics": true
      }
   },
   "inputs": [
      {
         "id": "278c54f2-f62c-4efd-b4f8-50d14c4ee337",
         "name": "system-1",
         "revision": 2,
         "type": "logfile",
         "use_output": "remote_not_es",
         "meta": {
            "package": {
               "name": "system",
               "version": "0.11.2"
            }
         },
         "data_stream": {
            "namespace": "default"
         },
         "streams": [
            {
               "id": "logfile-system.auth-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.auth",
                  "type": "logs"
               },
               "exclude_files": [
                  ".gz$"
               ],
               "paths": [
                  "/var/log/auth.log*",
                  "/var/log/secure*"
               ],
               "multiline": {
                  "pattern": "^\\s",
                  "match": "after"
               },
               "processors": [
                  {
                     "add_locale": null
                  },
                  {
                     "add_fields": {
                        "fields": {
                           "ecs.version": "1.8.0"
                        },
                        "target": ""
                     }
                  }
               ]
            },
            {
               "id": "logfile-system.syslog-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.syslog",
                  "type": "logs"
               },
               "exclude_files": [
                  ".gz$"
               ],
               "paths": [
                  "/var/log/messages*",
                  "/var/log/syslog*"
               ],
               "multiline": {
                  "pattern": "^\\s",
                  "match": "after"
               },
               "processors": [
                  {
                     "add_locale": null
                  },
                  {
                     "add_fields": {
                        "fields": {
                           "ecs.version": "1.5.0"
                        },
                        "target": ""
                     }
                  }
               ]
            }
         ]
      },
      {
         "id": "278c54f2-f62c-4efd-b4f8-50d14c4ee337",
         "name": "system-1",
         "revision": 2,
         "type": "system/metrics",
         "use_output": "remote_not_es",
         "meta": {
            "package": {
               "name": "system",
               "version": "0.11.2"
            }
         },
         "data_stream": {
            "namespace": "default"
         },
         "streams": [
            {
               "id": "system/metrics-system.cpu-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.cpu",
                  "type": "metrics"
               },
               "period": "10s",
               "cpu.metrics": [
                  "percentages",
                  "normalized_percentages"
               ],
               "metricsets": [
                  "cpu"
               ]
            },
            {
               "id": "system/metrics-system.diskio-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.diskio",
                  "type": "metrics"
               },
               "period": "10s",
               "diskio.include_devices": null,
               "metricsets": [
                  "diskio"
               ]
            },
            {
               "id": "system/metrics-system.filesystem-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.filesystem",
                  "type": "metrics"
               },
               "period": "1m",
               "metricsets": [
                  "filesystem"
               ],
               "processors": [
                  {
                     "drop_event.when.regexp": {
                        "system.filesystem.mount_point": "^/(sys|cgroup|proc|dev|etc|host|lib|snap)($|/)"
                     }
                  }
               ]
            },
            {
               "id": "system/metrics-system.fsstat-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.fsstat",
                  "type": "metrics"
               },
               "period": "1m",
               "metricsets": [
                  "fsstat"
               ],
               "processors": [
                  {
                     "drop_event.when.regexp": {
                        "system.fsstat.mount_point": "^/(sys|cgroup|proc|dev|etc|host|lib|snap)($|/)"
                     }
                  }
               ]
            },
            {
               "id": "system/metrics-system.load-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.load",
                  "type": "metrics"
               },
               "condition": "${host.platform} != 'windows'",
               "period": "10s",
               "metricsets": [
                  "load"
               ]
            },
            {
               "id": "system/metrics-system.memory-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.memory",
                  "type": "metrics"
               },
               "period": "10s",
               "metricsets": [
                  "memory"
               ]
            },
            {
               "id": "system/metrics-system.network-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.network",
                  "type": "metrics"
               },
               "period": "10s",
               "network.interfaces": null,
               "metricsets": [
                  "network"
               ]
            },
            {
               "id": "system/metrics-system.process-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.process",
                  "type": "metrics"
               },
               "process.include_top_n.by_memory": 5,
               "period": "10s",
               "processes": [
                  ".*"
               ],
               "process.include_top_n.by_cpu": 5,
               "process.cgroups.enabled": false,
               "process.cmdline.cache.enabled": true,
               "metricsets": [
                  "process"
               ],
               "process.include_cpu_ticks": false
            },
            {
               "id": "system/metrics-system.process_summary-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.process_summary",
                  "type": "metrics"
               },
               "period": "10s",
               "metricsets": [
                  "process_summary"
               ]
            },
            {
               "id": "system/metrics-system.socket_summary-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.socket_summary",
                  "type": "metrics"
               },
               "period": "10s",
               "metricsets": [
                  "socket_summary"
               ]
            },
            {
               "id": "system/metrics-system.uptime-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.uptime",
                  "type": "metrics"
               },
               "period": "10s",
               "metricsets": [
                  "uptime"
               ]
            }
         ]
      },
      {
         "id": "74abb3e2-a041-4684-8b3d-09e0e5eacd36",
         "name": "Endgame",
         "revision": 28,
         "type": "endpoint",
         "use_output": "remote_not_es",
         "meta": {
            "package": {
               "name": "endpoint",
               "version": "0.18.0"
            }
         },
         "data_stream": {
            "namespace": "default"
         },
         "artifact_manifest": {
            "schema_version": "v1",
            "manifest_version": "1.0.28",
            "artifacts": {
               "endpoint-trustlist-windows-v1": {
                  "relative_url": "/api/endpoint/artifacts/download/endpoint-trustlist-windows-v1/74c2255ce31e0b48ada298ed6dacf6d1be7b0fb40c1bcb251d2da66f4b060acf",
                  "compression_algorithm": "zlib",
                  "decoded_size": 338,
                  "decoded_sha256": "74c2255ce31e0b48ada298ed6dacf6d1be7b0fb40c1bcb251d2da66f4b060acf",
                  "encryption_algorithm": "none",
                  "encoded_sha256": "8e70ce05d25709b6bbd4fd6981e86e24e1a2f85e3f69d2733058c568830f25d2",
                  "encoded_size": 185
               },
               "endpoint-trustlist-macos-v1": {
                  "relative_url": "/api/endpoint/artifacts/download/endpoint-trustlist-macos-v1/d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658",
                  "compression_algorithm": "zlib",
                  "decoded_size": 14,
                  "decoded_sha256": "d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658",
                  "encryption_algorithm": "none",
                  "encoded_sha256": "f8e6afa1d5662f5b37f83337af774b5785b5b7f1daee08b7b00c2d6813874cda",
                  "encoded_size": 22
               },
               "endpoint-exceptionlist-macos-v1": {
                  "relative_url": "/api/endpoint/artifacts/download/endpoint-exceptionlist-macos-v1/d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658",
                  "compression_algorithm": "zlib",
                  "decoded_size": 14,
                  "decoded_sha256": "d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658",
                  "encryption_algorithm": "none",
                  "encoded_sha256": "f8e6afa1d5662f5b37f83337af774b5785b5b7f1daee08b7b00c2d6813874cda",
                  "encoded_size": 22
               },
               "endpoint-trustlist-linux-v1": {
                  "relative_url": "/api/endpoint/artifacts/download/endpoint-trustlist-linux-v1/d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658",
                  "compression_algorithm": "zlib",
                  "decoded_size": 14,
                  "decoded_sha256": "d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658",
                  "encryption_algorithm": "none",
                  "encoded_sha256": "f8e6afa1d5662f5b37f83337af774b5785b5b7f1daee08b7b00c2d6813874cda",
                  "encoded_size": 22
               },
               "endpoint-exceptionlist-windows-v1": {
                  "relative_url": "/api/endpoint/artifacts/download/endpoint-exceptionlist-windows-v1/d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658",
                  "compression_algorithm": "zlib",
                  "decoded_size": 14,
                  "decoded_sha256": "d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658",
                  "encryption_algorithm": "none",
                  "encoded_sha256": "f8e6afa1d5662f5b37f83337af774b5785b5b7f1daee08b7b00c2d6813874cda",
                  "encoded_size": 22
               }
            }
         },
         "policy": {
            "linux": {
               "logging": {
                  "file": "info"
               },
               "events": {
                  "process": true,
                  "file": true,
                  "network": true
               }
            },
            "windows": {
               "popup": {
                  "malware": {
                     "enabled": true,
                     "message": ""
                  },
                  "ransomware": {
                     "enabled": true,
                     "message": ""
                  }
               },
               "malware": {
                  "mode": "prevent"
               },
               "logging": {
                  "file": "info"
               },
               "antivirus_registration": {
                  "enabled": false
               },
               "events": {
                  "registry": true,
                  "process": true,
                  "security": true,
                  "file": true,
                  "dns": true,
                  "dll_and_driver_load": true,
                  "network": true
               },
               "ransomware": {
                  "mode": "prevent"
               }
            },
            "mac": {
               "popup": {
                  "malware": {
                     "enabled": true,
                     "message": ""
                  }
               },
               "malware": {
                  "mode": "prevent"
               },
               "logging": {
                  "file": "info"
               },
               "events": {
                  "process": true,
                  "file": true,
                  "network": true
               }
            }
         }
      }
   ],
   "fleet": {
      "hosts": [
         "http://10.128.0.4:8220"
      ]
   }
}
`

const minified = `
{"id":"63f4e6d0-9626-11eb-b486-6de1529a4151","revision":33,"outputs":{"default":{"type":"elasticsearch","hosts":["https://5a8bb94bfbe0401a909e1496a9e884c2.us-central1.gcp.foundit.no:443"]}},"output_permissions":{"default":{"_fallback":{"cluster":["monitor"],"indices":[{"names":["logs-*","metrics-*","traces-*",".logs-endpoint.diagnostic.collection-*"],"privileges":["auto_configure","create_doc"]}]}}},"agent":{"monitoring":{"enabled":true,"remote_not_es":"default","logs":true,"metrics":true}},"inputs":[{"id":"278c54f2-f62c-4efd-b4f8-50d14c4ee337","name":"system-1","revision":2,"type":"logfile","use_output":"default","meta":{"package":{"name":"system","version":"0.11.2"}},"data_stream":{"namespace":"default"},"streams":[{"id":"logfile-system.auth-278c54f2-f62c-4efd-b4f8-50d14c4ee337","data_stream":{"dataset":"system.auth","type":"logs"},"exclude_files":[".gz$"],"paths":["/var/log/auth.log*","/var/log/secure*"],"multiline":{"pattern":"^\\s","match":"after"},"processors":[{"add_locale":null},{"add_fields":{"fields":{"ecs.version":"1.8.0"},"target":""}}]},{"id":"logfile-system.syslog-278c54f2-f62c-4efd-b4f8-50d14c4ee337","data_stream":{"dataset":"system.syslog","type":"logs"},"exclude_files":[".gz$"],"paths":["/var/log/messages*","/var/log/syslog*"],"multiline":{"pattern":"^\\s","match":"after"},"processors":[{"add_locale":null},{"add_fields":{"fields":{"ecs.version":"1.5.0"},"target":""}}]}]},{"id":"278c54f2-f62c-4efd-b4f8-50d14c4ee337","name":"system-1","revision":2,"type":"system/metrics","use_output":"default","meta":{"package":{"name":"system","version":"0.11.2"}},"data_stream":{"namespace":"default"},"streams":[{"id":"system/metrics-system.cpu-278c54f2-f62c-4efd-b4f8-50d14c4ee337","data_stream":{"dataset":"system.cpu","type":"metrics"},"period":"10s","cpu.metrics":["percentages","normalized_percentages"],"metricsets":["cpu"]},{"id":"system/metrics-system.diskio-278c54f2-f62c-4efd-b4f8-50d14c4ee337","data_stream":{"dataset":"system.diskio","type":"metrics"},"period":"10s","diskio.include_devices":null,"metricsets":["diskio"]},{"id":"system/metrics-system.filesystem-278c54f2-f62c-4efd-b4f8-50d14c4ee337","data_stream":{"dataset":"system.filesystem","type":"metrics"},"period":"1m","metricsets":["filesystem"],"processors":[{"drop_event.when.regexp":{"system.filesystem.mount_point":"^/(sys|cgroup|proc|dev|etc|host|lib|snap)($|/)"}}]},{"id":"system/metrics-system.fsstat-278c54f2-f62c-4efd-b4f8-50d14c4ee337","data_stream":{"dataset":"system.fsstat","type":"metrics"},"period":"1m","metricsets":["fsstat"],"processors":[{"drop_event.when.regexp":{"system.fsstat.mount_point":"^/(sys|cgroup|proc|dev|etc|host|lib|snap)($|/)"}}]},{"id":"system/metrics-system.load-278c54f2-f62c-4efd-b4f8-50d14c4ee337","data_stream":{"dataset":"system.load","type":"metrics"},"condition":"${host.platform} != 'windows'","period":"10s","metricsets":["load"]},{"id":"system/metrics-system.memory-278c54f2-f62c-4efd-b4f8-50d14c4ee337","data_stream":{"dataset":"system.memory","type":"metrics"},"period":"10s","metricsets":["memory"]},{"id":"system/metrics-system.network-278c54f2-f62c-4efd-b4f8-50d14c4ee337","data_stream":{"dataset":"system.network","type":"metrics"},"period":"10s","network.interfaces":null,"metricsets":["network"]},{"id":"system/metrics-system.process-278c54f2-f62c-4efd-b4f8-50d14c4ee337","data_stream":{"dataset":"system.process","type":"metrics"},"process.include_top_n.by_memory":5,"period":"10s","processes":[".*"],"process.include_top_n.by_cpu":5,"process.cgroups.enabled":false,"process.cmdline.cache.enabled":true,"metricsets":["process"],"process.include_cpu_ticks":false},{"id":"system/metrics-system.process_summary-278c54f2-f62c-4efd-b4f8-50d14c4ee337","data_stream":{"dataset":"system.process_summary","type":"metrics"},"period":"10s","metricsets":["process_summary"]},{"id":"system/metrics-system.socket_summary-278c54f2-f62c-4efd-b4f8-50d14c4ee337","data_stream":{"dataset":"system.socket_summary","type":"metrics"},"period":"10s","metricsets":["socket_summary"]},{"id":"system/metrics-system.uptime-278c54f2-f62c-4efd-b4f8-50d14c4ee337","data_stream":{"dataset":"system.uptime","type":"metrics"},"period":"10s","metricsets":["uptime"]}]},{"id":"74abb3e2-a041-4684-8b3d-09e0e5eacd36","name":"Endgame","revision":28,"type":"endpoint","use_output":"default","meta":{"package":{"name":"endpoint","version":"0.18.0"}},"data_stream":{"namespace":"default"},"artifact_manifest":{"schema_version":"v1","manifest_version":"1.0.28","artifacts":{"endpoint-trustlist-windows-v1":{"relative_url":"/api/endpoint/artifacts/download/endpoint-trustlist-windows-v1/74c2255ce31e0b48ada298ed6dacf6d1be7b0fb40c1bcb251d2da66f4b060acf","compression_algorithm":"zlib","decoded_size":338,"decoded_sha256":"74c2255ce31e0b48ada298ed6dacf6d1be7b0fb40c1bcb251d2da66f4b060acf","encryption_algorithm":"none","encoded_sha256":"8e70ce05d25709b6bbd4fd6981e86e24e1a2f85e3f69d2733058c568830f25d2","encoded_size":185},"endpoint-trustlist-macos-v1":{"relative_url":"/api/endpoint/artifacts/download/endpoint-trustlist-macos-v1/d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658","compression_algorithm":"zlib","decoded_size":14,"decoded_sha256":"d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658","encryption_algorithm":"none","encoded_sha256":"f8e6afa1d5662f5b37f83337af774b5785b5b7f1daee08b7b00c2d6813874cda","encoded_size":22},"endpoint-exceptionlist-macos-v1":{"relative_url":"/api/endpoint/artifacts/download/endpoint-exceptionlist-macos-v1/d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658","compression_algorithm":"zlib","decoded_size":14,"decoded_sha256":"d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658","encryption_algorithm":"none","encoded_sha256":"f8e6afa1d5662f5b37f83337af774b5785b5b7f1daee08b7b00c2d6813874cda","encoded_size":22},"endpoint-trustlist-linux-v1":{"relative_url":"/api/endpoint/artifacts/download/endpoint-trustlist-linux-v1/d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658","compression_algorithm":"zlib","decoded_size":14,"decoded_sha256":"d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658","encryption_algorithm":"none","encoded_sha256":"f8e6afa1d5662f5b37f83337af774b5785b5b7f1daee08b7b00c2d6813874cda","encoded_size":22},"endpoint-exceptionlist-windows-v1":{"relative_url":"/api/endpoint/artifacts/download/endpoint-exceptionlist-windows-v1/d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658","compression_algorithm":"zlib","decoded_size":14,"decoded_sha256":"d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658","encryption_algorithm":"none","encoded_sha256":"f8e6afa1d5662f5b37f83337af774b5785b5b7f1daee08b7b00c2d6813874cda","encoded_size":22}}},"policy":{"linux":{"logging":{"file":"info"},"events":{"process":true,"file":true,"network":true}},"windows":{"popup":{"malware":{"enabled":true,"message":""},"ransomware":{"enabled":true,"message":""}},"malware":{"mode":"prevent"},"logging":{"file":"info"},"antivirus_registration":{"enabled":false},"events":{"registry":true,"process":true,"security":true,"file":true,"dns":true,"dll_and_driver_load":true,"network":true},"ransomware":{"mode":"prevent"}},"mac":{"popup":{"malware":{"enabled":true,"message":""}},"malware":{"mode":"prevent"},"logging":{"file":"info"},"events":{"process":true,"file":true,"network":true}}}}],"fleet":{"hosts":["http://10.128.0.4:8220"]}}`

const logstashOutputPolicy = `
{
   "id": "63f4e6d0-9626-11eb-b486-6de1529a4151",
   "revision": 33,
   "outputs": {
      "remote_not_es": {
         "type": "logstash",
         "hosts": [
            "https://5a8bb94bfbe0401a909e1496a9e884c2.us-central1.gcp.foundit.no:443"
         ]
      }
   },
   "agent": {
      "monitoring": {
         "enabled": true,
         "use_output": "remote_not_es",
         "logs": true,
         "metrics": true
      }
   },
   "inputs": [
      {
         "id": "278c54f2-f62c-4efd-b4f8-50d14c4ee337",
         "name": "system-1",
         "revision": 2,
         "type": "system/metrics",
         "use_output": "remote_not_es",
         "meta": {
            "package": {
               "name": "system",
               "version": "0.11.2"
            }
         },
         "data_stream": {
            "namespace": "default"
         },
         "streams": [
            {
               "id": "system/metrics-system.cpu-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.cpu",
                  "type": "metrics"
               },
               "period": "10s",
               "cpu.metrics": [
                  "percentages",
                  "normalized_percentages"
               ],
               "metricsets": [
                  "cpu"
               ]
            },
            {
               "id": "system/metrics-system.diskio-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.diskio",
                  "type": "metrics"
               },
               "period": "10s",
               "diskio.include_devices": null,
               "metricsets": [
                  "diskio"
               ]
            },
            {
               "id": "system/metrics-system.filesystem-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.filesystem",
                  "type": "metrics"
               },
               "period": "1m",
               "metricsets": [
                  "filesystem"
               ],
               "processors": [
                  {
                     "drop_event.when.regexp": {
                        "system.filesystem.mount_point": "^/(sys|cgroup|proc|dev|etc|host|lib|snap)($|/)"
                     }
                  }
               ]
            },
            {
               "id": "system/metrics-system.fsstat-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.fsstat",
                  "type": "metrics"
               },
               "period": "1m",
               "metricsets": [
                  "fsstat"
               ],
               "processors": [
                  {
                     "drop_event.when.regexp": {
                        "system.fsstat.mount_point": "^/(sys|cgroup|proc|dev|etc|host|lib|snap)($|/)"
                     }
                  }
               ]
            },
            {
               "id": "system/metrics-system.load-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.load",
                  "type": "metrics"
               },
               "condition": "${host.platform} != 'windows'",
               "period": "10s",
               "metricsets": [
                  "load"
               ]
            },
            {
               "id": "system/metrics-system.memory-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.memory",
                  "type": "metrics"
               },
               "period": "10s",
               "metricsets": [
                  "memory"
               ]
            },
            {
               "id": "system/metrics-system.network-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.network",
                  "type": "metrics"
               },
               "period": "10s",
               "network.interfaces": null,
               "metricsets": [
                  "network"
               ]
            },
            {
               "id": "system/metrics-system.process-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.process",
                  "type": "metrics"
               },
               "process.include_top_n.by_memory": 5,
               "period": "10s",
               "processes": [
                  ".*"
               ],
               "process.include_top_n.by_cpu": 5,
               "process.cgroups.enabled": false,
               "process.cmdline.cache.enabled": true,
               "metricsets": [
                  "process"
               ],
               "process.include_cpu_ticks": false
            },
            {
               "id": "system/metrics-system.process_summary-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.process_summary",
                  "type": "metrics"
               },
               "period": "10s",
               "metricsets": [
                  "process_summary"
               ]
            },
            {
               "id": "system/metrics-system.socket_summary-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.socket_summary",
                  "type": "metrics"
               },
               "period": "10s",
               "metricsets": [
                  "socket_summary"
               ]
            },
            {
               "id": "system/metrics-system.uptime-278c54f2-f62c-4efd-b4f8-50d14c4ee337",
               "data_stream": {
                  "dataset": "system.uptime",
                  "type": "metrics"
               },
               "period": "10s",
               "metricsets": [
                  "uptime"
               ]
            }
         ]
      }
   ],
   "fleet": {
      "hosts": [
         "http://10.128.0.4:8220"
      ]
   }
}
`
