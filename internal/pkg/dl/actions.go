// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
	"github.com/rs/zerolog"
)

const (
	FieldAgents      = "agents"
	FieldExpiration  = "expiration"
	FieldSize        = "size"
	FieldTraceparent = "traceparent"

	maxAgentActionsFetchSize = 100
)

var (
	QueryAction          = prepareFindAction()
	QueryAllAgentActions = prepareFindAllAgentsActions()
	QueryAgentActions    = prepareFindAgentActions()

	// Query for expired actions GC
	QueryDeleteExpiredActions = prepareDeleteExpiredAction()
	QueryFindExpiredActions   = prepareFindExpiredAction()
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
	filter.Term(FieldActionID, tmpl.Bind(FieldActionID), nil)
	root.Size(1)
	root.Source().Includes(FieldActionID, FiledType, FieldNamespaces, FieldTraceparent)
	tmpl.MustResolve(root)
	return tmpl
}

func prepareDeleteExpiredAction() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	filter := root.Query().Bool().Filter()
	filter.Range(FieldExpiration, dsl.WithRangeLTE(tmpl.Bind(FieldExpiration)))
	tmpl.MustResolve(root)
	return tmpl
}

func prepareFindExpiredAction() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	filter := root.Query().Bool().Filter()
	filter.Range(FieldExpiration, dsl.WithRangeLTE(tmpl.Bind(FieldExpiration)))
	// Select only acton ids for deletion
	root.Source().Includes("_id")
	root.WithSize(tmpl.Bind(FieldSize))
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
	return //nolint:nakedret // simple function
}

func FindAction(ctx context.Context, bulker bulk.Bulk, id string, opts ...Option) (model.Action, error) {
	o := newOption(FleetActions, opts...)
	query, err := QueryAction.RenderOne(FieldActionID, id)
	if err != nil {
		return model.Action{}, err
	}
	res, err := findActionsHits(ctx, bulker, o.indexName, query, nil)
	if err != nil {
		return model.Action{}, err
	}
	if res == nil || len(res.Hits) == 0 {
		return model.Action{}, ErrNotFound
	}
	if len(res.Hits) > 1 {
		return model.Action{}, fmt.Errorf("find action %q: only one hit is expected, got %d", id, len(res.Hits))
	}
	actions, err := hitsToActions(res.Hits)
	if err != nil {
		return model.Action{}, err
	}
	return actions[0], nil
}

func FindAgentActions(ctx context.Context, bulker bulk.Bulk, minSeqNo, maxSeqNo sqn.SeqNo, agentID string) ([]model.Action, error) {
	const index = FleetActions
	query, err := QueryAgentActions.Render(map[string]any{
		FieldSeqNo:      minSeqNo.Value(),
		FieldMaxSeqNo:   maxSeqNo.Value(),
		FieldExpiration: time.Now().UTC().Format(time.RFC3339),
		FieldAgents:     []string{agentID},
	})
	if err != nil {
		return nil, err
	}

	res, err := findActionsHits(ctx, bulker, index, query, maxSeqNo)
	if err != nil || res == nil {
		return nil, err
	}

	return hitsToActions(res.Hits)
}

func DeleteExpiredForIndex(ctx context.Context, index string, bulker bulk.Bulk, cleanupIntervalAfterExpired string) (int64, error) {
	params := map[string]any{
		FieldExpiration: "now-" + cleanupIntervalAfterExpired,
	}

	query, err := QueryDeleteExpiredActions.Render(params)
	if err != nil {
		return 0, err
	}

	res, err := bulker.Client().DeleteByQuery([]string{index}, bytes.NewReader(query),
		bulker.Client().DeleteByQuery.WithContext(ctx))

	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	var esres es.DeleteByQueryResponse

	err = json.NewDecoder(res.Body).Decode(&esres)
	if err != nil {
		return 0, err
	}

	if res.IsError() {
		err = es.TranslateError(res.StatusCode, esres.Error)
		if err != nil {
			if errors.Is(err, es.ErrIndexNotFound) {
				zerolog.Ctx(ctx).Debug().Str("index", index).Msg(es.ErrIndexNotFound.Error())
				err = nil
			}
			return 0, err
		}
	}

	return esres.Deleted, nil
}

func FindExpiredActionsHitsForIndex(ctx context.Context, index string, bulker bulk.Bulk, expiredBefore time.Time, size int) ([]es.HitT, error) {
	query, err := QueryFindExpiredActions.Render(map[string]any{
		FieldExpiration: expiredBefore.UTC().Format(time.RFC3339),
		FieldSize:       size,
	})
	if err != nil {
		return nil, err
	}

	res, err := findActionsHits(ctx, bulker, index, query, nil)
	if err != nil || res == nil {
		return nil, err
	}
	return res.Hits, nil
}

func findActionsHits(ctx context.Context, bulker bulk.Bulk, index string, query []byte, seqNos []int64) (*es.HitsT, error) {
	var ops []bulk.Opt
	if len(seqNos) > 0 {
		ops = append(ops, bulk.WithWaitForCheckpoints(seqNos))
	}
	res, err := bulker.Search(ctx, index, query, ops...)
	if err != nil {
		if errors.Is(err, es.ErrIndexNotFound) {
			zerolog.Ctx(ctx).Debug().Str("index", index).Msg(es.ErrIndexNotFound.Error())
			err = nil
		}
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	return &res.HitsT, nil
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
