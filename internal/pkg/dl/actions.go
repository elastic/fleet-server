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
)

const (
	FieldAgents     = "agents"
	FieldExpiration = "expiration"
)

type ActionDoc struct {
	model.Action
	DocID string
	SeqNo int64
}

func PrepareAllAgentActionsQuery() (tmpl *dsl.Tmpl, err error) {
	tmpl, root, _ := createBaseActionsQuery()
	if err := tmpl.Resolve(root); err != nil {
		return nil, err
	}
	return
}

func PrepareAgentActionsQuery() (tmpl *dsl.Tmpl, err error) {
	tmpl, root, filter := createBaseActionsQuery()

	filter.Terms(FieldAgents, tmpl.Bind(FieldAgents), nil)

	root.Source().Excludes(FieldAgents)

	if err := tmpl.Resolve(root); err != nil {
		return nil, err
	}

	return
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

func SearchActions(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, params map[string]interface{}) ([]ActionDoc, error) {
	return searchActions(ctx, bulker, tmpl, FleetActions, params)
}

func searchActions(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, index string, params map[string]interface{}) ([]ActionDoc, error) {
	res, err := Search(ctx, bulker, tmpl, index, params)
	if err != nil {
		return nil, err
	}

	docs := make([]ActionDoc, len(res.Hits))

	for i, hit := range res.Hits {
		var action model.Action
		err = json.Unmarshal(hit.Source, &action)
		if err != nil {
			return nil, err
		}
		docs[i] = ActionDoc{action, hit.Id, hit.SeqNo}
	}
	return docs, err
}
