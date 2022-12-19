// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"fmt"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

const (
	FieldAccessAPIKeyID = "access_api_key_id"
)

var (
	QueryAgentByAssessAPIKeyID   = prepareAgentFindByAccessAPIKeyID()
	QueryAgentByID               = prepareAgentFindByID()
	QueryOfflineAgentsByPolicyID = prepareOfflineAgentsByPolicyID()
)

func prepareAgentFindByID() *dsl.Tmpl {
	return prepareAgentFindByField(FieldID)
}

func prepareAgentFindByAccessAPIKeyID() *dsl.Tmpl {
	return prepareAgentFindByField(FieldAccessAPIKeyID)
}

func prepareAgentFindByField(field string) *dsl.Tmpl {
	return prepareFindByField(field, map[string]interface{}{"version": true})
}

func prepareOfflineAgentsByPolicyID() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()

	root := dsl.NewRoot()
	filter := root.Query().Bool().Filter()
	filter.Term(FieldActive, true, nil)
	filter.Term(FieldPolicyID, tmpl.Bind(FieldPolicyID), nil)
	filter.Range(FieldLastCheckin, dsl.WithRangeLTE(tmpl.Bind(FieldLastCheckin)))

	tmpl.MustResolve(root)
	return tmpl
}

func FindAgent(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, name string, v interface{}, opt ...Option) (model.Agent, error) {
	o := newOption(FleetAgents, opt...)
	res, err := SearchWithOneParam(ctx, bulker, tmpl, o.indexName, name, v)
	if err != nil {
		return model.Agent{}, fmt.Errorf("failed searching for agent: %w", err)
	}

	if len(res.Hits) == 0 {
		return model.Agent{}, ErrNotFound
	}

	var agent model.Agent
	if err = res.Hits[0].Unmarshal(&agent); err != nil {
		return model.Agent{}, fmt.Errorf("could not unmarshal ES document into model.Agent: %w", err)
	}

	return agent, nil
}
