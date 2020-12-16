// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"context"
	"fleet/internal/pkg/config"
	"fleet/internal/pkg/es"
	"fleet/internal/pkg/esboot"
	"fmt"
)

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

// Setup for integration testing
// Create the indices and data streams
func main() {
	fmt.Println("Setting up the indices")

	cfg, err := config.LoadFile("fleet-server.yml")
	checkErr(err)

	ctx := context.Background()
	es, err := es.NewClient(ctx, cfg)
	checkErr(err)

	err = esboot.EnsureESIndices(ctx, es)
	checkErr(err)

	// Create .kibana index for integration tests
	// This temporarily until all the parts are unplugged from .kibana
	// Otherwise the fleet server fails to start at the moment
	err = esboot.EnsureIndex(ctx, es, ".kibana", kibanaMapping)
	checkErr(err)
}

const kibanaMapping = `{
	"dynamic" : "strict",
	"properties" : {
	  "action" : {
		"properties" : {
		  "actionTypeId" : {
			"type" : "keyword"
		  },
		  "config" : {
			"type" : "object",
			"enabled" : false
		  },
		  "name" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword"
			  }
			}
		  },
		  "secrets" : {
			"type" : "binary"
		  }
		}
	  },
	  "action_task_params" : {
		"properties" : {
		  "actionId" : {
			"type" : "keyword"
		  },
		  "apiKey" : {
			"type" : "binary"
		  },
		  "params" : {
			"type" : "object",
			"enabled" : false
		  }
		}
	  },
	  "alert" : {
		"properties" : {
		  "actions" : {
			"type" : "nested",
			"properties" : {
			  "actionRef" : {
				"type" : "keyword"
			  },
			  "actionTypeId" : {
				"type" : "keyword"
			  },
			  "group" : {
				"type" : "keyword"
			  },
			  "params" : {
				"type" : "object",
				"enabled" : false
			  }
			}
		  },
		  "alertTypeId" : {
			"type" : "keyword"
		  },
		  "apiKey" : {
			"type" : "binary"
		  },
		  "apiKeyOwner" : {
			"type" : "keyword"
		  },
		  "consumer" : {
			"type" : "keyword"
		  },
		  "createdAt" : {
			"type" : "date"
		  },
		  "createdBy" : {
			"type" : "keyword"
		  },
		  "enabled" : {
			"type" : "boolean"
		  },
		  "executionStatus" : {
			"properties" : {
			  "error" : {
				"properties" : {
				  "message" : {
					"type" : "keyword"
				  },
				  "reason" : {
					"type" : "keyword"
				  }
				}
			  },
			  "lastExecutionDate" : {
				"type" : "date"
			  },
			  "status" : {
				"type" : "keyword"
			  }
			}
		  },
		  "meta" : {
			"properties" : {
			  "versionApiKeyLastmodified" : {
				"type" : "keyword"
			  }
			}
		  },
		  "muteAll" : {
			"type" : "boolean"
		  },
		  "mutedInstanceIds" : {
			"type" : "keyword"
		  },
		  "name" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword"
			  }
			}
		  },
		  "params" : {
			"type" : "object",
			"enabled" : false
		  },
		  "schedule" : {
			"properties" : {
			  "interval" : {
				"type" : "keyword"
			  }
			}
		  },
		  "scheduledTaskId" : {
			"type" : "keyword"
		  },
		  "tags" : {
			"type" : "keyword"
		  },
		  "throttle" : {
			"type" : "keyword"
		  },
		  "updatedAt" : {
			"type" : "date"
		  },
		  "updatedBy" : {
			"type" : "keyword"
		  }
		}
	  },
	  "api_key_pending_invalidation" : {
		"properties" : {
		  "apiKeyId" : {
			"type" : "keyword"
		  },
		  "createdAt" : {
			"type" : "date"
		  }
		}
	  },
	  "apm-indices" : {
		"properties" : {
		  "apm_oss" : {
			"properties" : {
			  "errorIndices" : {
				"type" : "keyword"
			  },
			  "metricsIndices" : {
				"type" : "keyword"
			  },
			  "onboardingIndices" : {
				"type" : "keyword"
			  },
			  "sourcemapIndices" : {
				"type" : "keyword"
			  },
			  "spanIndices" : {
				"type" : "keyword"
			  },
			  "transactionIndices" : {
				"type" : "keyword"
			  }
			}
		  }
		}
	  },
	  "apm-telemetry" : {
		"type" : "object",
		"dynamic" : "false"
	  },
	  "app_search_telemetry" : {
		"type" : "object",
		"dynamic" : "false"
	  },
	  "application_usage_daily" : {
		"dynamic" : "false",
		"properties" : {
		  "timestamp" : {
			"type" : "date"
		  }
		}
	  },
	  "application_usage_totals" : {
		"type" : "object",
		"dynamic" : "false"
	  },
	  "application_usage_transactional" : {
		"type" : "object",
		"dynamic" : "false"
	  },
	  "background-session" : {
		"properties" : {
		  "created" : {
			"type" : "date"
		  },
		  "expires" : {
			"type" : "date"
		  },
		  "idMapping" : {
			"type" : "object",
			"enabled" : false
		  },
		  "initialState" : {
			"type" : "object",
			"enabled" : false
		  },
		  "name" : {
			"type" : "keyword"
		  },
		  "restoreState" : {
			"type" : "object",
			"enabled" : false
		  },
		  "status" : {
			"type" : "keyword"
		  }
		}
	  },
	  "book" : {
		"properties" : {
		  "author" : {
			"type" : "keyword"
		  },
		  "readIt" : {
			"type" : "boolean"
		  },
		  "title" : {
			"type" : "keyword"
		  }
		}
	  },
	  "canvas-element" : {
		"dynamic" : "false",
		"properties" : {
		  "@created" : {
			"type" : "date"
		  },
		  "@timestamp" : {
			"type" : "date"
		  },
		  "content" : {
			"type" : "text"
		  },
		  "help" : {
			"type" : "text"
		  },
		  "image" : {
			"type" : "text"
		  },
		  "name" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword"
			  }
			}
		  }
		}
	  },
	  "canvas-workpad" : {
		"dynamic" : "false",
		"properties" : {
		  "@created" : {
			"type" : "date"
		  },
		  "@timestamp" : {
			"type" : "date"
		  },
		  "name" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword"
			  }
			}
		  }
		}
	  },
	  "canvas-workpad-template" : {
		"dynamic" : "false",
		"properties" : {
		  "help" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword"
			  }
			}
		  },
		  "name" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword"
			  }
			}
		  },
		  "tags" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword"
			  }
			}
		  },
		  "template_key" : {
			"type" : "keyword"
		  }
		}
	  },
	  "cases" : {
		"properties" : {
		  "closed_at" : {
			"type" : "date"
		  },
		  "closed_by" : {
			"properties" : {
			  "email" : {
				"type" : "keyword"
			  },
			  "full_name" : {
				"type" : "keyword"
			  },
			  "username" : {
				"type" : "keyword"
			  }
			}
		  },
		  "connector" : {
			"properties" : {
			  "fields" : {
				"properties" : {
				  "key" : {
					"type" : "text"
				  },
				  "value" : {
					"type" : "text"
				  }
				}
			  },
			  "id" : {
				"type" : "keyword"
			  },
			  "name" : {
				"type" : "text"
			  },
			  "type" : {
				"type" : "keyword"
			  }
			}
		  },
		  "created_at" : {
			"type" : "date"
		  },
		  "created_by" : {
			"properties" : {
			  "email" : {
				"type" : "keyword"
			  },
			  "full_name" : {
				"type" : "keyword"
			  },
			  "username" : {
				"type" : "keyword"
			  }
			}
		  },
		  "description" : {
			"type" : "text"
		  },
		  "external_service" : {
			"properties" : {
			  "connector_id" : {
				"type" : "keyword"
			  },
			  "connector_name" : {
				"type" : "keyword"
			  },
			  "external_id" : {
				"type" : "keyword"
			  },
			  "external_title" : {
				"type" : "text"
			  },
			  "external_url" : {
				"type" : "text"
			  },
			  "pushed_at" : {
				"type" : "date"
			  },
			  "pushed_by" : {
				"properties" : {
				  "email" : {
					"type" : "keyword"
				  },
				  "full_name" : {
					"type" : "keyword"
				  },
				  "username" : {
					"type" : "keyword"
				  }
				}
			  }
			}
		  },
		  "status" : {
			"type" : "keyword"
		  },
		  "tags" : {
			"type" : "keyword"
		  },
		  "title" : {
			"type" : "keyword"
		  },
		  "updated_at" : {
			"type" : "date"
		  },
		  "updated_by" : {
			"properties" : {
			  "email" : {
				"type" : "keyword"
			  },
			  "full_name" : {
				"type" : "keyword"
			  },
			  "username" : {
				"type" : "keyword"
			  }
			}
		  }
		}
	  },
	  "cases-comments" : {
		"properties" : {
		  "alertId" : {
			"type" : "keyword"
		  },
		  "comment" : {
			"type" : "text"
		  },
		  "created_at" : {
			"type" : "date"
		  },
		  "created_by" : {
			"properties" : {
			  "email" : {
				"type" : "keyword"
			  },
			  "full_name" : {
				"type" : "keyword"
			  },
			  "username" : {
				"type" : "keyword"
			  }
			}
		  },
		  "index" : {
			"type" : "keyword"
		  },
		  "pushed_at" : {
			"type" : "date"
		  },
		  "pushed_by" : {
			"properties" : {
			  "email" : {
				"type" : "keyword"
			  },
			  "full_name" : {
				"type" : "keyword"
			  },
			  "username" : {
				"type" : "keyword"
			  }
			}
		  },
		  "type" : {
			"type" : "keyword"
		  },
		  "updated_at" : {
			"type" : "date"
		  },
		  "updated_by" : {
			"properties" : {
			  "email" : {
				"type" : "keyword"
			  },
			  "full_name" : {
				"type" : "keyword"
			  },
			  "username" : {
				"type" : "keyword"
			  }
			}
		  }
		}
	  },
	  "cases-configure" : {
		"properties" : {
		  "closure_type" : {
			"type" : "keyword"
		  },
		  "connector" : {
			"properties" : {
			  "fields" : {
				"properties" : {
				  "key" : {
					"type" : "text"
				  },
				  "value" : {
					"type" : "text"
				  }
				}
			  },
			  "id" : {
				"type" : "keyword"
			  },
			  "name" : {
				"type" : "text"
			  },
			  "type" : {
				"type" : "keyword"
			  }
			}
		  },
		  "created_at" : {
			"type" : "date"
		  },
		  "created_by" : {
			"properties" : {
			  "email" : {
				"type" : "keyword"
			  },
			  "full_name" : {
				"type" : "keyword"
			  },
			  "username" : {
				"type" : "keyword"
			  }
			}
		  },
		  "updated_at" : {
			"type" : "date"
		  },
		  "updated_by" : {
			"properties" : {
			  "email" : {
				"type" : "keyword"
			  },
			  "full_name" : {
				"type" : "keyword"
			  },
			  "username" : {
				"type" : "keyword"
			  }
			}
		  }
		}
	  },
	  "cases-user-actions" : {
		"properties" : {
		  "action" : {
			"type" : "keyword"
		  },
		  "action_at" : {
			"type" : "date"
		  },
		  "action_by" : {
			"properties" : {
			  "email" : {
				"type" : "keyword"
			  },
			  "full_name" : {
				"type" : "keyword"
			  },
			  "username" : {
				"type" : "keyword"
			  }
			}
		  },
		  "action_field" : {
			"type" : "keyword"
		  },
		  "new_value" : {
			"type" : "text"
		  },
		  "old_value" : {
			"type" : "text"
		  }
		}
	  },
	  "config" : {
		"dynamic" : "false",
		"properties" : {
		  "buildNum" : {
			"type" : "keyword"
		  }
		}
	  },
	  "dashboard" : {
		"properties" : {
		  "description" : {
			"type" : "text"
		  },
		  "hits" : {
			"type" : "integer",
			"index" : false,
			"doc_values" : false
		  },
		  "kibanaSavedObjectMeta" : {
			"properties" : {
			  "searchSourceJSON" : {
				"type" : "text",
				"index" : false
			  }
			}
		  },
		  "optionsJSON" : {
			"type" : "text",
			"index" : false
		  },
		  "panelsJSON" : {
			"type" : "text",
			"index" : false
		  },
		  "refreshInterval" : {
			"properties" : {
			  "display" : {
				"type" : "keyword",
				"index" : false,
				"doc_values" : false
			  },
			  "pause" : {
				"type" : "boolean",
				"doc_values" : false,
				"index" : false
			  },
			  "section" : {
				"type" : "integer",
				"index" : false,
				"doc_values" : false
			  },
			  "value" : {
				"type" : "integer",
				"index" : false,
				"doc_values" : false
			  }
			}
		  },
		  "timeFrom" : {
			"type" : "keyword",
			"index" : false,
			"doc_values" : false
		  },
		  "timeRestore" : {
			"type" : "boolean",
			"doc_values" : false,
			"index" : false
		  },
		  "timeTo" : {
			"type" : "keyword",
			"index" : false,
			"doc_values" : false
		  },
		  "title" : {
			"type" : "text"
		  },
		  "version" : {
			"type" : "integer"
		  }
		}
	  },
	  "endpoint:user-artifact" : {
		"properties" : {
		  "body" : {
			"type" : "binary"
		  },
		  "compressionAlgorithm" : {
			"type" : "keyword",
			"index" : false
		  },
		  "created" : {
			"type" : "date",
			"index" : false
		  },
		  "decodedSha256" : {
			"type" : "keyword",
			"index" : false
		  },
		  "decodedSize" : {
			"type" : "long",
			"index" : false
		  },
		  "encodedSha256" : {
			"type" : "keyword"
		  },
		  "encodedSize" : {
			"type" : "long",
			"index" : false
		  },
		  "encryptionAlgorithm" : {
			"type" : "keyword",
			"index" : false
		  },
		  "identifier" : {
			"type" : "keyword"
		  }
		}
	  },
	  "endpoint:user-artifact-manifest" : {
		"properties" : {
		  "created" : {
			"type" : "date",
			"index" : false
		  },
		  "ids" : {
			"type" : "keyword",
			"index" : false
		  },
		  "schemaVersion" : {
			"type" : "keyword"
		  },
		  "semanticVersion" : {
			"type" : "keyword",
			"index" : false
		  }
		}
	  },
	  "enterprise_search_telemetry" : {
		"type" : "object",
		"dynamic" : "false"
	  },
	  "epm-packages" : {
		"properties" : {
		  "es_index_patterns" : {
			"type" : "object",
			"enabled" : false
		  },
		  "install_source" : {
			"type" : "keyword"
		  },
		  "install_started_at" : {
			"type" : "date"
		  },
		  "install_status" : {
			"type" : "keyword"
		  },
		  "install_version" : {
			"type" : "keyword"
		  },
		  "installed_es" : {
			"type" : "nested",
			"properties" : {
			  "id" : {
				"type" : "keyword"
			  },
			  "type" : {
				"type" : "keyword"
			  }
			}
		  },
		  "installed_kibana" : {
			"type" : "nested",
			"properties" : {
			  "id" : {
				"type" : "keyword"
			  },
			  "type" : {
				"type" : "keyword"
			  }
			}
		  },
		  "internal" : {
			"type" : "boolean"
		  },
		  "name" : {
			"type" : "keyword"
		  },
		  "removable" : {
			"type" : "boolean"
		  },
		  "version" : {
			"type" : "keyword"
		  }
		}
	  },
	  "exception-list" : {
		"properties" : {
		  "_tags" : {
			"type" : "keyword"
		  },
		  "comments" : {
			"properties" : {
			  "comment" : {
				"type" : "keyword"
			  },
			  "created_at" : {
				"type" : "keyword"
			  },
			  "created_by" : {
				"type" : "keyword"
			  },
			  "id" : {
				"type" : "keyword"
			  },
			  "updated_at" : {
				"type" : "keyword"
			  },
			  "updated_by" : {
				"type" : "keyword"
			  }
			}
		  },
		  "created_at" : {
			"type" : "keyword"
		  },
		  "created_by" : {
			"type" : "keyword"
		  },
		  "description" : {
			"type" : "keyword"
		  },
		  "entries" : {
			"properties" : {
			  "entries" : {
				"properties" : {
				  "field" : {
					"type" : "keyword"
				  },
				  "operator" : {
					"type" : "keyword"
				  },
				  "type" : {
					"type" : "keyword"
				  },
				  "value" : {
					"type" : "keyword",
					"fields" : {
					  "text" : {
						"type" : "text"
					  }
					}
				  }
				}
			  },
			  "field" : {
				"type" : "keyword"
			  },
			  "list" : {
				"properties" : {
				  "id" : {
					"type" : "keyword"
				  },
				  "type" : {
					"type" : "keyword"
				  }
				}
			  },
			  "operator" : {
				"type" : "keyword"
			  },
			  "type" : {
				"type" : "keyword"
			  },
			  "value" : {
				"type" : "keyword",
				"fields" : {
				  "text" : {
					"type" : "text"
				  }
				}
			  }
			}
		  },
		  "immutable" : {
			"type" : "boolean"
		  },
		  "item_id" : {
			"type" : "keyword"
		  },
		  "list_id" : {
			"type" : "keyword"
		  },
		  "list_type" : {
			"type" : "keyword"
		  },
		  "meta" : {
			"type" : "keyword"
		  },
		  "name" : {
			"type" : "keyword"
		  },
		  "os_types" : {
			"type" : "keyword"
		  },
		  "tags" : {
			"type" : "keyword"
		  },
		  "tie_breaker_id" : {
			"type" : "keyword"
		  },
		  "type" : {
			"type" : "keyword"
		  },
		  "updated_by" : {
			"type" : "keyword"
		  },
		  "version" : {
			"type" : "keyword"
		  }
		}
	  },
	  "exception-list-agnostic" : {
		"properties" : {
		  "_tags" : {
			"type" : "keyword"
		  },
		  "comments" : {
			"properties" : {
			  "comment" : {
				"type" : "keyword"
			  },
			  "created_at" : {
				"type" : "keyword"
			  },
			  "created_by" : {
				"type" : "keyword"
			  },
			  "id" : {
				"type" : "keyword"
			  },
			  "updated_at" : {
				"type" : "keyword"
			  },
			  "updated_by" : {
				"type" : "keyword"
			  }
			}
		  },
		  "created_at" : {
			"type" : "keyword"
		  },
		  "created_by" : {
			"type" : "keyword"
		  },
		  "description" : {
			"type" : "keyword"
		  },
		  "entries" : {
			"properties" : {
			  "entries" : {
				"properties" : {
				  "field" : {
					"type" : "keyword"
				  },
				  "operator" : {
					"type" : "keyword"
				  },
				  "type" : {
					"type" : "keyword"
				  },
				  "value" : {
					"type" : "keyword",
					"fields" : {
					  "text" : {
						"type" : "text"
					  }
					}
				  }
				}
			  },
			  "field" : {
				"type" : "keyword"
			  },
			  "list" : {
				"properties" : {
				  "id" : {
					"type" : "keyword"
				  },
				  "type" : {
					"type" : "keyword"
				  }
				}
			  },
			  "operator" : {
				"type" : "keyword"
			  },
			  "type" : {
				"type" : "keyword"
			  },
			  "value" : {
				"type" : "keyword",
				"fields" : {
				  "text" : {
					"type" : "text"
				  }
				}
			  }
			}
		  },
		  "immutable" : {
			"type" : "boolean"
		  },
		  "item_id" : {
			"type" : "keyword"
		  },
		  "list_id" : {
			"type" : "keyword"
		  },
		  "list_type" : {
			"type" : "keyword"
		  },
		  "meta" : {
			"type" : "keyword"
		  },
		  "name" : {
			"type" : "keyword"
		  },
		  "os_types" : {
			"type" : "keyword"
		  },
		  "tags" : {
			"type" : "keyword"
		  },
		  "tie_breaker_id" : {
			"type" : "keyword"
		  },
		  "type" : {
			"type" : "keyword"
		  },
		  "updated_by" : {
			"type" : "keyword"
		  },
		  "version" : {
			"type" : "keyword"
		  }
		}
	  },
	  "file-upload-telemetry" : {
		"properties" : {
		  "filesUploadedTotalCount" : {
			"type" : "long"
		  }
		}
	  },
	  "fleet-agent-actions" : {
		"properties" : {
		  "ack_data" : {
			"type" : "text"
		  },
		  "agent_id" : {
			"type" : "keyword"
		  },
		  "created_at" : {
			"type" : "date"
		  },
		  "data" : {
			"type" : "binary"
		  },
		  "policy_id" : {
			"type" : "keyword"
		  },
		  "policy_revision" : {
			"type" : "integer"
		  },
		  "sent_at" : {
			"type" : "date"
		  },
		  "type" : {
			"type" : "keyword"
		  }
		}
	  },
	  "fleet-agent-events" : {
		"properties" : {
		  "action_id" : {
			"type" : "keyword"
		  },
		  "agent_id" : {
			"type" : "keyword"
		  },
		  "data" : {
			"type" : "text"
		  },
		  "message" : {
			"type" : "text"
		  },
		  "payload" : {
			"type" : "text"
		  },
		  "policy_id" : {
			"type" : "keyword"
		  },
		  "stream_id" : {
			"type" : "keyword"
		  },
		  "subtype" : {
			"type" : "keyword"
		  },
		  "timestamp" : {
			"type" : "date"
		  },
		  "type" : {
			"type" : "keyword"
		  }
		}
	  },
	  "fleet-agents" : {
		"properties" : {
		  "access_api_key_id" : {
			"type" : "keyword"
		  },
		  "active" : {
			"type" : "boolean"
		  },
		  "current_error_events" : {
			"type" : "text",
			"index" : false
		  },
		  "default_api_key" : {
			"type" : "binary"
		  },
		  "default_api_key_id" : {
			"type" : "keyword"
		  },
		  "enrolled_at" : {
			"type" : "date"
		  },
		  "last_checkin" : {
			"type" : "date"
		  },
		  "last_checkin_status" : {
			"type" : "keyword"
		  },
		  "last_updated" : {
			"type" : "date"
		  },
		  "local_metadata" : {
			"type" : "flattened"
		  },
		  "packages" : {
			"type" : "keyword"
		  },
		  "policy_id" : {
			"type" : "keyword"
		  },
		  "policy_revision" : {
			"type" : "integer"
		  },
		  "shared_id" : {
			"type" : "keyword"
		  },
		  "type" : {
			"type" : "keyword"
		  },
		  "unenrolled_at" : {
			"type" : "date"
		  },
		  "unenrollment_started_at" : {
			"type" : "date"
		  },
		  "updated_at" : {
			"type" : "date"
		  },
		  "upgrade_started_at" : {
			"type" : "date"
		  },
		  "upgraded_at" : {
			"type" : "date"
		  },
		  "user_provided_metadata" : {
			"type" : "flattened"
		  },
		  "version" : {
			"type" : "keyword"
		  }
		}
	  },
	  "fleet-enrollment-api-keys" : {
		"properties" : {
		  "active" : {
			"type" : "boolean"
		  },
		  "api_key" : {
			"type" : "binary"
		  },
		  "api_key_id" : {
			"type" : "keyword"
		  },
		  "created_at" : {
			"type" : "date"
		  },
		  "expire_at" : {
			"type" : "date"
		  },
		  "name" : {
			"type" : "keyword"
		  },
		  "policy_id" : {
			"type" : "keyword"
		  },
		  "type" : {
			"type" : "keyword"
		  },
		  "updated_at" : {
			"type" : "date"
		  }
		}
	  },
	  "graph-workspace" : {
		"properties" : {
		  "description" : {
			"type" : "text"
		  },
		  "kibanaSavedObjectMeta" : {
			"properties" : {
			  "searchSourceJSON" : {
				"type" : "text"
			  }
			}
		  },
		  "numLinks" : {
			"type" : "integer"
		  },
		  "numVertices" : {
			"type" : "integer"
		  },
		  "title" : {
			"type" : "text"
		  },
		  "version" : {
			"type" : "integer"
		  },
		  "wsState" : {
			"type" : "text"
		  }
		}
	  },
	  "index-pattern" : {
		"dynamic" : "false",
		"properties" : {
		  "title" : {
			"type" : "text"
		  },
		  "type" : {
			"type" : "keyword"
		  }
		}
	  },
	  "infrastructure-ui-source" : {
		"type" : "object",
		"dynamic" : "false"
	  },
	  "ingest-agent-policies" : {
		"properties" : {
		  "description" : {
			"type" : "text"
		  },
		  "is_default" : {
			"type" : "boolean"
		  },
		  "monitoring_enabled" : {
			"type" : "keyword",
			"index" : false
		  },
		  "name" : {
			"type" : "keyword"
		  },
		  "namespace" : {
			"type" : "keyword"
		  },
		  "package_policies" : {
			"type" : "keyword"
		  },
		  "revision" : {
			"type" : "integer"
		  },
		  "status" : {
			"type" : "keyword"
		  },
		  "updated_at" : {
			"type" : "date"
		  },
		  "updated_by" : {
			"type" : "keyword"
		  }
		}
	  },
	  "ingest-outputs" : {
		"properties" : {
		  "ca_sha256" : {
			"type" : "keyword",
			"index" : false
		  },
		  "config" : {
			"type" : "flattened"
		  },
		  "config_yaml" : {
			"type" : "text"
		  },
		  "fleet_enroll_password" : {
			"type" : "binary"
		  },
		  "fleet_enroll_username" : {
			"type" : "binary"
		  },
		  "hosts" : {
			"type" : "keyword"
		  },
		  "is_default" : {
			"type" : "boolean"
		  },
		  "name" : {
			"type" : "keyword"
		  },
		  "type" : {
			"type" : "keyword"
		  }
		}
	  },
	  "ingest-package-policies" : {
		"properties" : {
		  "created_at" : {
			"type" : "date"
		  },
		  "created_by" : {
			"type" : "keyword"
		  },
		  "description" : {
			"type" : "text"
		  },
		  "enabled" : {
			"type" : "boolean"
		  },
		  "inputs" : {
			"type" : "nested",
			"enabled" : false,
			"properties" : {
			  "config" : {
				"type" : "flattened"
			  },
			  "enabled" : {
				"type" : "boolean"
			  },
			  "streams" : {
				"type" : "nested",
				"properties" : {
				  "compiled_stream" : {
					"type" : "flattened"
				  },
				  "config" : {
					"type" : "flattened"
				  },
				  "data_stream" : {
					"properties" : {
					  "dataset" : {
						"type" : "keyword"
					  },
					  "type" : {
						"type" : "keyword"
					  }
					}
				  },
				  "enabled" : {
					"type" : "boolean"
				  },
				  "id" : {
					"type" : "keyword"
				  },
				  "vars" : {
					"type" : "flattened"
				  }
				}
			  },
			  "type" : {
				"type" : "keyword"
			  },
			  "vars" : {
				"type" : "flattened"
			  }
			}
		  },
		  "name" : {
			"type" : "keyword"
		  },
		  "namespace" : {
			"type" : "keyword"
		  },
		  "output_id" : {
			"type" : "keyword"
		  },
		  "package" : {
			"properties" : {
			  "name" : {
				"type" : "keyword"
			  },
			  "title" : {
				"type" : "keyword"
			  },
			  "version" : {
				"type" : "keyword"
			  }
			}
		  },
		  "policy_id" : {
			"type" : "keyword"
		  },
		  "revision" : {
			"type" : "integer"
		  },
		  "updated_at" : {
			"type" : "date"
		  },
		  "updated_by" : {
			"type" : "keyword"
		  }
		}
	  },
	  "ingest_manager_settings" : {
		"properties" : {
		  "agent_auto_upgrade" : {
			"type" : "keyword"
		  },
		  "has_seen_add_data_notice" : {
			"type" : "boolean",
			"index" : false
		  },
		  "kibana_ca_sha256" : {
			"type" : "keyword"
		  },
		  "kibana_urls" : {
			"type" : "keyword"
		  },
		  "package_auto_upgrade" : {
			"type" : "keyword"
		  }
		}
	  },
	  "inventory-view" : {
		"type" : "object",
		"dynamic" : "false"
	  },
	  "kql-telemetry" : {
		"properties" : {
		  "optInCount" : {
			"type" : "long"
		  },
		  "optOutCount" : {
			"type" : "long"
		  }
		}
	  },
	  "lens" : {
		"properties" : {
		  "description" : {
			"type" : "text"
		  },
		  "expression" : {
			"type" : "keyword",
			"index" : false,
			"doc_values" : false
		  },
		  "state" : {
			"type" : "flattened"
		  },
		  "title" : {
			"type" : "text"
		  },
		  "visualizationType" : {
			"type" : "keyword"
		  }
		}
	  },
	  "lens-ui-telemetry" : {
		"properties" : {
		  "count" : {
			"type" : "integer"
		  },
		  "date" : {
			"type" : "date"
		  },
		  "name" : {
			"type" : "keyword"
		  },
		  "type" : {
			"type" : "keyword"
		  }
		}
	  },
	  "map" : {
		"properties" : {
		  "description" : {
			"type" : "text"
		  },
		  "layerListJSON" : {
			"type" : "text"
		  },
		  "mapStateJSON" : {
			"type" : "text"
		  },
		  "title" : {
			"type" : "text"
		  },
		  "uiStateJSON" : {
			"type" : "text"
		  },
		  "version" : {
			"type" : "integer"
		  }
		}
	  },
	  "maps-telemetry" : {
		"type" : "object",
		"enabled" : false
	  },
	  "metrics-explorer-view" : {
		"type" : "object",
		"dynamic" : "false"
	  },
	  "migrationVersion" : {
		"dynamic" : "true",
		"properties" : {
		  "config" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword",
				"ignore_above" : 256
			  }
			}
		  },
		  "space" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword",
				"ignore_above" : 256
			  }
			}
		  }
		}
	  },
	  "ml-job" : {
		"properties" : {
		  "datafeed_id" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword"
			  }
			}
		  },
		  "job_id" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword"
			  }
			}
		  },
		  "type" : {
			"type" : "keyword"
		  }
		}
	  },
	  "ml-telemetry" : {
		"properties" : {
		  "file_data_visualizer" : {
			"properties" : {
			  "index_creation_count" : {
				"type" : "long"
			  }
			}
		  }
		}
	  },
	  "monitoring-telemetry" : {
		"properties" : {
		  "reportedClusterUuids" : {
			"type" : "keyword"
		  }
		}
	  },
	  "namespace" : {
		"type" : "keyword"
	  },
	  "namespaces" : {
		"type" : "keyword"
	  },
	  "originId" : {
		"type" : "keyword"
	  },
	  "query" : {
		"properties" : {
		  "description" : {
			"type" : "text"
		  },
		  "filters" : {
			"type" : "object",
			"enabled" : false
		  },
		  "query" : {
			"properties" : {
			  "language" : {
				"type" : "keyword"
			  },
			  "query" : {
				"type" : "keyword",
				"index" : false
			  }
			}
		  },
		  "timefilter" : {
			"type" : "object",
			"enabled" : false
		  },
		  "title" : {
			"type" : "text"
		  }
		}
	  },
	  "references" : {
		"type" : "nested",
		"properties" : {
		  "id" : {
			"type" : "keyword"
		  },
		  "name" : {
			"type" : "keyword"
		  },
		  "type" : {
			"type" : "keyword"
		  }
		}
	  },
	  "sample-data-telemetry" : {
		"properties" : {
		  "installCount" : {
			"type" : "long"
		  },
		  "unInstallCount" : {
			"type" : "long"
		  }
		}
	  },
	  "search" : {
		"properties" : {
		  "columns" : {
			"type" : "keyword",
			"index" : false,
			"doc_values" : false
		  },
		  "description" : {
			"type" : "text"
		  },
		  "hits" : {
			"type" : "integer",
			"index" : false,
			"doc_values" : false
		  },
		  "kibanaSavedObjectMeta" : {
			"properties" : {
			  "searchSourceJSON" : {
				"type" : "text",
				"index" : false
			  }
			}
		  },
		  "sort" : {
			"type" : "keyword",
			"index" : false,
			"doc_values" : false
		  },
		  "title" : {
			"type" : "text"
		  },
		  "version" : {
			"type" : "integer"
		  }
		}
	  },
	  "search-telemetry" : {
		"type" : "object",
		"dynamic" : "false"
	  },
	  "siem-detection-engine-rule-actions" : {
		"properties" : {
		  "actions" : {
			"properties" : {
			  "action_type_id" : {
				"type" : "keyword"
			  },
			  "group" : {
				"type" : "keyword"
			  },
			  "id" : {
				"type" : "keyword"
			  },
			  "params" : {
				"type" : "object",
				"enabled" : false
			  }
			}
		  },
		  "alertThrottle" : {
			"type" : "keyword"
		  },
		  "ruleAlertId" : {
			"type" : "keyword"
		  },
		  "ruleThrottle" : {
			"type" : "keyword"
		  }
		}
	  },
	  "siem-detection-engine-rule-status" : {
		"properties" : {
		  "alertId" : {
			"type" : "keyword"
		  },
		  "bulkCreateTimeDurations" : {
			"type" : "float"
		  },
		  "gap" : {
			"type" : "text"
		  },
		  "lastFailureAt" : {
			"type" : "date"
		  },
		  "lastFailureMessage" : {
			"type" : "text"
		  },
		  "lastLookBackDate" : {
			"type" : "date"
		  },
		  "lastSuccessAt" : {
			"type" : "date"
		  },
		  "lastSuccessMessage" : {
			"type" : "text"
		  },
		  "searchAfterTimeDurations" : {
			"type" : "float"
		  },
		  "status" : {
			"type" : "keyword"
		  },
		  "statusDate" : {
			"type" : "date"
		  }
		}
	  },
	  "siem-ui-timeline" : {
		"properties" : {
		  "columns" : {
			"properties" : {
			  "aggregatable" : {
				"type" : "boolean"
			  },
			  "category" : {
				"type" : "keyword"
			  },
			  "columnHeaderType" : {
				"type" : "keyword"
			  },
			  "description" : {
				"type" : "text"
			  },
			  "example" : {
				"type" : "text"
			  },
			  "id" : {
				"type" : "keyword"
			  },
			  "indexes" : {
				"type" : "keyword"
			  },
			  "name" : {
				"type" : "text"
			  },
			  "placeholder" : {
				"type" : "text"
			  },
			  "searchable" : {
				"type" : "boolean"
			  },
			  "type" : {
				"type" : "keyword"
			  }
			}
		  },
		  "created" : {
			"type" : "date"
		  },
		  "createdBy" : {
			"type" : "text"
		  },
		  "dataProviders" : {
			"properties" : {
			  "and" : {
				"properties" : {
				  "enabled" : {
					"type" : "boolean"
				  },
				  "excluded" : {
					"type" : "boolean"
				  },
				  "id" : {
					"type" : "keyword"
				  },
				  "kqlQuery" : {
					"type" : "text"
				  },
				  "name" : {
					"type" : "text"
				  },
				  "queryMatch" : {
					"properties" : {
					  "displayField" : {
						"type" : "text"
					  },
					  "displayValue" : {
						"type" : "text"
					  },
					  "field" : {
						"type" : "text"
					  },
					  "operator" : {
						"type" : "text"
					  },
					  "value" : {
						"type" : "text"
					  }
					}
				  },
				  "type" : {
					"type" : "text"
				  }
				}
			  },
			  "enabled" : {
				"type" : "boolean"
			  },
			  "excluded" : {
				"type" : "boolean"
			  },
			  "id" : {
				"type" : "keyword"
			  },
			  "kqlQuery" : {
				"type" : "text"
			  },
			  "name" : {
				"type" : "text"
			  },
			  "queryMatch" : {
				"properties" : {
				  "displayField" : {
					"type" : "text"
				  },
				  "displayValue" : {
					"type" : "text"
				  },
				  "field" : {
					"type" : "text"
				  },
				  "operator" : {
					"type" : "text"
				  },
				  "value" : {
					"type" : "text"
				  }
				}
			  },
			  "type" : {
				"type" : "text"
			  }
			}
		  },
		  "dateRange" : {
			"properties" : {
			  "end" : {
				"type" : "date"
			  },
			  "start" : {
				"type" : "date"
			  }
			}
		  },
		  "description" : {
			"type" : "text"
		  },
		  "eventType" : {
			"type" : "keyword"
		  },
		  "excludedRowRendererIds" : {
			"type" : "text"
		  },
		  "favorite" : {
			"properties" : {
			  "favoriteDate" : {
				"type" : "date"
			  },
			  "fullName" : {
				"type" : "text"
			  },
			  "keySearch" : {
				"type" : "text"
			  },
			  "userName" : {
				"type" : "text"
			  }
			}
		  },
		  "filters" : {
			"properties" : {
			  "exists" : {
				"type" : "text"
			  },
			  "match_all" : {
				"type" : "text"
			  },
			  "meta" : {
				"properties" : {
				  "alias" : {
					"type" : "text"
				  },
				  "controlledBy" : {
					"type" : "text"
				  },
				  "disabled" : {
					"type" : "boolean"
				  },
				  "field" : {
					"type" : "text"
				  },
				  "formattedValue" : {
					"type" : "text"
				  },
				  "index" : {
					"type" : "keyword"
				  },
				  "key" : {
					"type" : "keyword"
				  },
				  "negate" : {
					"type" : "boolean"
				  },
				  "params" : {
					"type" : "text"
				  },
				  "type" : {
					"type" : "keyword"
				  },
				  "value" : {
					"type" : "text"
				  }
				}
			  },
			  "missing" : {
				"type" : "text"
			  },
			  "query" : {
				"type" : "text"
			  },
			  "range" : {
				"type" : "text"
			  },
			  "script" : {
				"type" : "text"
			  }
			}
		  },
		  "indexNames" : {
			"type" : "text"
		  },
		  "kqlMode" : {
			"type" : "keyword"
		  },
		  "kqlQuery" : {
			"properties" : {
			  "filterQuery" : {
				"properties" : {
				  "kuery" : {
					"properties" : {
					  "expression" : {
						"type" : "text"
					  },
					  "kind" : {
						"type" : "keyword"
					  }
					}
				  },
				  "serializedQuery" : {
					"type" : "text"
				  }
				}
			  }
			}
		  },
		  "savedQueryId" : {
			"type" : "keyword"
		  },
		  "sort" : {
			"properties" : {
			  "columnId" : {
				"type" : "keyword"
			  },
			  "sortDirection" : {
				"type" : "keyword"
			  }
			}
		  },
		  "status" : {
			"type" : "keyword"
		  },
		  "templateTimelineId" : {
			"type" : "text"
		  },
		  "templateTimelineVersion" : {
			"type" : "integer"
		  },
		  "timelineType" : {
			"type" : "keyword"
		  },
		  "title" : {
			"type" : "text"
		  },
		  "updated" : {
			"type" : "date"
		  },
		  "updatedBy" : {
			"type" : "text"
		  }
		}
	  },
	  "siem-ui-timeline-note" : {
		"properties" : {
		  "created" : {
			"type" : "date"
		  },
		  "createdBy" : {
			"type" : "text"
		  },
		  "eventId" : {
			"type" : "keyword"
		  },
		  "note" : {
			"type" : "text"
		  },
		  "timelineId" : {
			"type" : "keyword"
		  },
		  "updated" : {
			"type" : "date"
		  },
		  "updatedBy" : {
			"type" : "text"
		  }
		}
	  },
	  "siem-ui-timeline-pinned-event" : {
		"properties" : {
		  "created" : {
			"type" : "date"
		  },
		  "createdBy" : {
			"type" : "text"
		  },
		  "eventId" : {
			"type" : "keyword"
		  },
		  "timelineId" : {
			"type" : "keyword"
		  },
		  "updated" : {
			"type" : "date"
		  },
		  "updatedBy" : {
			"type" : "text"
		  }
		}
	  },
	  "space" : {
		"properties" : {
		  "_reserved" : {
			"type" : "boolean"
		  },
		  "color" : {
			"type" : "keyword"
		  },
		  "description" : {
			"type" : "text"
		  },
		  "disabledFeatures" : {
			"type" : "keyword"
		  },
		  "imageUrl" : {
			"type" : "text",
			"index" : false
		  },
		  "initials" : {
			"type" : "keyword"
		  },
		  "name" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword",
				"ignore_above" : 2048
			  }
			}
		  }
		}
	  },
	  "tag" : {
		"properties" : {
		  "color" : {
			"type" : "text"
		  },
		  "description" : {
			"type" : "text"
		  },
		  "name" : {
			"type" : "text"
		  }
		}
	  },
	  "telemetry" : {
		"properties" : {
		  "allowChangingOptInStatus" : {
			"type" : "boolean"
		  },
		  "enabled" : {
			"type" : "boolean"
		  },
		  "lastReported" : {
			"type" : "date"
		  },
		  "lastVersionChecked" : {
			"type" : "keyword"
		  },
		  "reportFailureCount" : {
			"type" : "integer"
		  },
		  "reportFailureVersion" : {
			"type" : "keyword"
		  },
		  "sendUsageFrom" : {
			"type" : "keyword"
		  },
		  "userHasSeenNotice" : {
			"type" : "boolean"
		  }
		}
	  },
	  "timelion-sheet" : {
		"properties" : {
		  "description" : {
			"type" : "text"
		  },
		  "hits" : {
			"type" : "integer"
		  },
		  "kibanaSavedObjectMeta" : {
			"properties" : {
			  "searchSourceJSON" : {
				"type" : "text"
			  }
			}
		  },
		  "timelion_chart_height" : {
			"type" : "integer"
		  },
		  "timelion_columns" : {
			"type" : "integer"
		  },
		  "timelion_interval" : {
			"type" : "keyword"
		  },
		  "timelion_other_interval" : {
			"type" : "keyword"
		  },
		  "timelion_rows" : {
			"type" : "integer"
		  },
		  "timelion_sheet" : {
			"type" : "text"
		  },
		  "title" : {
			"type" : "text"
		  },
		  "version" : {
			"type" : "integer"
		  }
		}
	  },
	  "todo" : {
		"properties" : {
		  "icon" : {
			"type" : "keyword"
		  },
		  "task" : {
			"type" : "text"
		  },
		  "title" : {
			"type" : "keyword"
		  }
		}
	  },
	  "tsvb-validation-telemetry" : {
		"properties" : {
		  "failedRequests" : {
			"type" : "long"
		  }
		}
	  },
	  "type" : {
		"type" : "keyword"
	  },
	  "ui-metric" : {
		"properties" : {
		  "count" : {
			"type" : "integer"
		  }
		}
	  },
	  "updated_at" : {
		"type" : "date"
	  },
	  "upgrade-assistant-reindex-operation" : {
		"properties" : {
		  "errorMessage" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword",
				"ignore_above" : 256
			  }
			}
		  },
		  "indexName" : {
			"type" : "keyword"
		  },
		  "lastCompletedStep" : {
			"type" : "long"
		  },
		  "locked" : {
			"type" : "date"
		  },
		  "newIndexName" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword",
				"ignore_above" : 256
			  }
			}
		  },
		  "reindexOptions" : {
			"properties" : {
			  "openAndClose" : {
				"type" : "boolean"
			  },
			  "queueSettings" : {
				"properties" : {
				  "queuedAt" : {
					"type" : "long"
				  },
				  "startedAt" : {
					"type" : "long"
				  }
				}
			  }
			}
		  },
		  "reindexTaskId" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword",
				"ignore_above" : 256
			  }
			}
		  },
		  "reindexTaskPercComplete" : {
			"type" : "float"
		  },
		  "runningReindexCount" : {
			"type" : "integer"
		  },
		  "status" : {
			"type" : "integer"
		  }
		}
	  },
	  "upgrade-assistant-telemetry" : {
		"properties" : {
		  "features" : {
			"properties" : {
			  "deprecation_logging" : {
				"properties" : {
				  "enabled" : {
					"type" : "boolean",
					"null_value" : true
				  }
				}
			  }
			}
		  },
		  "ui_open" : {
			"properties" : {
			  "cluster" : {
				"type" : "long",
				"null_value" : 0
			  },
			  "indices" : {
				"type" : "long",
				"null_value" : 0
			  },
			  "overview" : {
				"type" : "long",
				"null_value" : 0
			  }
			}
		  },
		  "ui_reindex" : {
			"properties" : {
			  "close" : {
				"type" : "long",
				"null_value" : 0
			  },
			  "open" : {
				"type" : "long",
				"null_value" : 0
			  },
			  "start" : {
				"type" : "long",
				"null_value" : 0
			  },
			  "stop" : {
				"type" : "long",
				"null_value" : 0
			  }
			}
		  }
		}
	  },
	  "uptime-dynamic-settings" : {
		"type" : "object",
		"dynamic" : "false"
	  },
	  "url" : {
		"properties" : {
		  "accessCount" : {
			"type" : "long"
		  },
		  "accessDate" : {
			"type" : "date"
		  },
		  "createDate" : {
			"type" : "date"
		  },
		  "url" : {
			"type" : "text",
			"fields" : {
			  "keyword" : {
				"type" : "keyword",
				"ignore_above" : 2048
			  }
			}
		  }
		}
	  },
	  "visualization" : {
		"properties" : {
		  "description" : {
			"type" : "text"
		  },
		  "kibanaSavedObjectMeta" : {
			"properties" : {
			  "searchSourceJSON" : {
				"type" : "text",
				"index" : false
			  }
			}
		  },
		  "savedSearchRefName" : {
			"type" : "keyword",
			"index" : false,
			"doc_values" : false
		  },
		  "title" : {
			"type" : "text"
		  },
		  "uiStateJSON" : {
			"type" : "text",
			"index" : false
		  },
		  "version" : {
			"type" : "integer"
		  },
		  "visState" : {
			"type" : "text",
			"index" : false
		  }
		}
	  },
	  "workplace_search_telemetry" : {
		"type" : "object",
		"dynamic" : "false"
	  }
	}
  }`
