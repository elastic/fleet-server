// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"errors"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
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

func FindAgentActions(ctx context.Context, bulker bulk.Bulk, minSeqNo, maxSeqNo sqn.SeqNo, agentId string) ([]model.Action, error) {
	const index = FleetActions
	params := map[string]interface{}{
		FieldSeqNo:      minSeqNo.Value(),
		FieldMaxSeqNo:   maxSeqNo.Value(),
		FieldExpiration: time.Now().UTC().Format(time.RFC3339),
		FieldAgents:     []string{agentId},
	}

	res, err := findActionsHits(ctx, bulker, QueryAgentActions, index, params)
	if err != nil || res == nil {
		return nil, err
	}

	if es.HasHoles(minSeqNo, res.Hits) {
		err = es.Refresh(ctx, bulker.Client(), index)
		if err != nil {
			log.Error().Err(err).Msg("failed to refresh index")
		}
		res, err := findActionsHits(ctx, bulker, QueryAgentActions, index, params)
		if err != nil || res == nil {
			return nil, err
		}
	}

	return hitsToActions(res.Hits)
}

func findActionsHits(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, index string, params map[string]interface{}) (*es.HitsT, error) {
	res, err := Search(ctx, bulker, tmpl, index, params)
	if err != nil {
		if errors.Is(err, es.ErrIndexNotFound) {
			log.Debug().Str("index", index).Msg(es.ErrIndexNotFound.Error())
			err = nil
		}
		return nil, err
	}
	return res, nil
}

func findActions(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, index string, params map[string]interface{}) ([]model.Action, error) {
	res, err := findActionsHits(ctx, bulker, tmpl, index, params)
	if err != nil || res == nil {
		return nil, err
	}

	return hitsToActions(res.Hits)
}

func hitsToActions(hits []es.HitT) ([]model.Action, error) {
	actions := make([]model.Action, 0, len(hits))

	for _, hit := range hits {
		var action model.Action
		err := hit.Unmarshal(&action)
		if err != nil {
			return nil, err
		}
		actions = append(actions, action)
	}
	return actions, nil
}
