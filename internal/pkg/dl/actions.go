// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"errors"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/rs/zerolog/log"
)

const (
	FieldAgents     = "agents"
	FieldExpiration = "expiration"

	maxAgentActionsFetchSize = 100
)

var (
	QueryAction          = prepareFindAction()
	QueryAllAgentActions = prepareFindAllAgentsActions()
	QueryAgentActions    = prepareFindAgentActions()
)

func prepareFindAllAgentsActions() *dsl.Tmpl {
	tmpl, root, _ := createBaseActionsQuery()
	tmpl.MustResolve(root)
	return tmpl
}

func prepareFindAction() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	filter := root.Query().Bool().Filter()
	filter.Term(FieldActionId, tmpl.Bind(FieldActionId), nil)
	root.Source().Excludes(FieldAgents)
	tmpl.MustResolve(root)
	return tmpl
}

func prepareFindAgentActions() *dsl.Tmpl {
	tmpl, root, filter := createBaseActionsQuery()

	filter.Terms(FieldAgents, tmpl.Bind(FieldAgents), nil)

	// Select more actions per agent since the agents array is not loaded
	root.Size(maxAgentActionsFetchSize)
	root.Source().Excludes(FieldAgents)

	tmpl.MustResolve(root)
	return tmpl
}

func createBaseActionsQuery() (tmpl *dsl.Tmpl, root, filter *dsl.Node) {
	tmpl = dsl.NewTmpl()

	root = dsl.NewRoot()
	root.Param(seqNoPrimaryTerm, true)

	filter = root.Query().Bool().Filter()
	filter.Range(FieldSeqNo, dsl.WithRangeGT(tmpl.Bind(FieldSeqNo)))
	filter.Range(FieldSeqNo, dsl.WithRangeLTE(tmpl.Bind(FieldMaxSeqNo)))
	filter.Range(FieldExpiration, dsl.WithRangeGT(tmpl.Bind(FieldExpiration)))

	root.Sort().SortOrder(FieldSeqNo, dsl.SortAscend)
	return
}

func FindAction(ctx context.Context, bulker bulk.Bulk, id string, opts ...Option) ([]model.Action, error) {
	o := newOption(FleetActions, opts...)
	return findActions(ctx, bulker, QueryAction, o.indexName, map[string]interface{}{
		FieldActionId: id,
	})
}

func FindActions(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, params map[string]interface{}) ([]model.Action, error) {
	return findActions(ctx, bulker, tmpl, FleetActions, params)
}

func findActions(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, index string, params map[string]interface{}) ([]model.Action, error) {
	res, err := Search(ctx, bulker, tmpl, index, params)
	if err != nil {
		if errors.Is(err, es.ErrIndexNotFound) {
			log.Debug().Str("index", index).Msg(es.ErrIndexNotFound.Error())
			err = nil
		}
		return nil, err
	}

	actions := make([]model.Action, 0, len(res.Hits))

	for _, hit := range res.Hits {
		var action model.Action
		err := hit.Unmarshal(&action)
		if err != nil {
			return nil, err
		}
		actions = append(actions, action)
	}
	return actions, err
}
