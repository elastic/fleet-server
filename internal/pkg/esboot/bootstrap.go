package esboot

import (
	"context"

	"github.com/elastic/go-elasticsearch/v8"
)

// Temporary ES indices bootstrapping until we move this logic to a proper place
// The plans at the moment possibly handle at ES plugin

const (
	agentMapping = `
	{
		"properties" : {
		  "agent" : {
			"properties": {
			  "id" : {
				"type" : "keyword"
			  },
			  "version" : {
				"type" : "keyword"
			  }
			}
		  },
		  "action_seq_no" : {
			"type" : "integer"
		  },
		  "local_metadata" : {
			"type" :"object"
		  },
		  "access_api_key" : {
			"type" : "keyword"
		  },
		  "access_api_key_id" : {
			"type" : "keyword"
		  },
		  "policy_id" : {
			"type" : "keyword"
		  },
		  "policy_revision" : {
			"type" : "integer"
		  },
		  "enrolled_at": {
			  "type": "date"
		  },
		  "unenrolled_at": {
			  "type": "date"
		  },
		  "enrollment_started_at": {
			  "type": "date"
		  },
		  "unenrollment_started_at": {
			  "type": "date"
		  },
		  "upgraded_at": {
			  "type": "date"
		  },
		  "upgrade_started_at": {
			  "type": "date"
		  },
		  "updated_at": {
			  "type": "date"
		  }
		}
	  }
	`

	actionsMapping = `
	{
		"properties" : {
		"data" : {
			"dynamic" : "false",
			"type": "object",
			"enabled": "false"
		},
		"@timestamp" : {
			"type" : "date"
		},
		"expiration" : {
			"type" : "date"
		},
		"id" : {
			"type" : "keyword"
		},
		"agents" : {
			"type" : "keyword"
		},
		"type" : {
			"type" : "keyword"
		},
		"application" : {
			"type" : "keyword"
		},
		"route" : {
			"type" : "keyword"
		}
		}
	}	
	`

	resultsMapping = `
	{
		"properties" : {
		"@timestamp" : {
			"type" : "date"
		},
		"agent" : {
			"type" : "keyword"
		},
		"action" : {
			"type" : "keyword"
		},
		"errors":  {
			"type" : "keyword"
		},
		"data" : {
			"dynamic" : "false",
			"type": "object",
			"enabled": "false"
		}
		}
	}	
	`
)

type indexConfig struct {
	mapping    string
	datastream bool
}

var indexConfigs = map[string]indexConfig{
	".fleet-agents":          {mapping: agentMapping},
	".fleet-actions":         {mapping: actionsMapping},
	".fleet-actions-results": {mapping: resultsMapping, datastream: true},
}

// Bootstrap creates .fleet-actions data stream
func EnsureESIndices(ctx context.Context, es *elasticsearch.Client) error {
	for name, idxcfg := range indexConfigs {
		err := EnsureDatastream(ctx, es, name, idxcfg)
		if err != nil {
			return err
		}
	}
	return nil
}

func EnsureDatastream(ctx context.Context, es *elasticsearch.Client, name string, idxcfg indexConfig) error {
	if idxcfg.datastream {
		err := EnsureILMPolicy(ctx, es, name)
		if err != nil {
			return err
		}
	}

	err := EnsureTemplate(ctx, es, name, idxcfg.mapping, idxcfg.datastream)
	if err != nil {
		return err
	}

	if idxcfg.datastream {
		err = CreateDatastream(ctx, es, name)
	} else {
		err = CreateIndex(ctx, es, name)
	}
	if err != nil {
		return err
	}

	return nil
}
