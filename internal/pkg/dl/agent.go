// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dsl"
	"fleet/internal/pkg/model"
)

var ErrAgentNotFound = errors.New("agent not found")

var (
	tmplQueryAgentByID     *dsl.Tmpl
	initQueryAgentByIDOnce sync.Once
)

func prepareQueryAgent() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Query().Bool().Filter().Term(FieldId, tmpl.Bind(FieldId), nil)

	return tmpl.MustResolve(root)
}

// QueryAgentById queries the agent by id.
func QueryAgentById(ctx context.Context, bulker bulk.Bulk, agentId string) (agent model.Agent, err error) {
	agent, err = queryAgentById(ctx, bulker, agentId)
	if err != nil {
		return
	}

	return
}

func QueryAgentActionSeqNo(ctx context.Context, bulker bulk.Bulk, agentId string) (seqno int64, err error) {
	agent, err := queryAgentById(ctx, bulker, agentId)

	_ = agent
	if err != nil {
		return
	}
	return agent.ActionSeqNo, nil
}

func queryAgentById(ctx context.Context, bulker bulk.Bulk, agentId string) (agent model.Agent, err error) {
	initQueryAgentByIDOnce.Do(func() {
		tmplQueryAgentByID = prepareQueryAgent()
	})

	query, err := tmplQueryAgentByID.RenderOne(FieldId, agentId)
	if err != nil {
		return
	}

	res, err := bulker.Search(ctx, []string{FleetAgents}, query)
	if err != nil {
		return
	}

	if len(res.Hits) == 0 {
		return agent, ErrAgentNotFound
	}

	hit := res.Hits[0]
	err = json.Unmarshal(hit.Source, &agent)

	return agent, err
}
