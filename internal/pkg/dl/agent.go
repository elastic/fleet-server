// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dsl"
	"fleet/internal/pkg/model"

	"github.com/gofrs/uuid"
)

const (
	FieldAccessAPIKeyID = "access_api_key_id"
)

var (
	QueryAgentByAssessAPIKeyID = prepareAgentFindByAccessAPIKeyID()
	QueryAgentByID             = prepareAgentFindByID()
)

func prepareAgentFindByID() *dsl.Tmpl {
	return prepareAgentFindByField(FieldId)
}

func prepareAgentFindByAccessAPIKeyID() *dsl.Tmpl {
	return prepareAgentFindByField(FieldAccessAPIKeyID)
}

func prepareAgentFindByField(field string) *dsl.Tmpl {
	return prepareFindByField(field, map[string]interface{}{"version": true})
}

func FindAgent(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, name string, v interface{}) (agent model.Agent, err error) {
	res, err := SearchWithOneParam(ctx, bulker, tmpl, FleetAgents, name, v)
	if err != nil {
		return
	}

	if len(res.Hits) == 0 {
		return agent, ErrNotFound
	}

	err = Unmarshal(res.Hits[0], &agent)
	return agent, err
}

func IndexAgent(ctx context.Context, bulker bulk.Bulk, agent model.Agent) error {
	if agent.Id == "" {
		agent.Id = uuid.Must(uuid.NewV4()).String()
	}
	body, err := json.Marshal(agent)
	if err != nil {
		return err
	}
	_, err = bulker.Index(ctx, FleetAgents, agent.Id, body, bulk.WithRefresh())
	return err
}
