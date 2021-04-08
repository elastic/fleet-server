// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
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

	err = res.Hits[0].Unmarshal(&agent)
	return agent, err
}
