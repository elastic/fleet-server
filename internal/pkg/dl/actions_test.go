// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

// fakeActionSearchBulk answers action searches from fixed data as Elasticsearch would.
type fakeActionSearchBulk struct {
	bulk.Bulk
	hits map[string][]es.HitT
	errs map[string]error
}

func (b *fakeActionSearchBulk) Search(_ context.Context, _ string, query []byte, _ ...bulk.Opt) (*es.ResultT, error) {
	var got struct {
		Size   int `json:"size"`
		Source struct {
			Includes []string `json:"includes"`
		} `json:"_source"`
		Query struct {
			Bool struct {
				Filter []struct {
					Term struct {
						ActionID string `json:"action_id"`
					} `json:"term"`
				} `json:"filter"`
			} `json:"bool"`
		} `json:"query"`
	}
	if err := json.Unmarshal(query, &got); err != nil {
		return nil, err
	}
	var actionID string
	for _, filter := range got.Query.Bool.Filter {
		if filter.Term.ActionID != "" {
			actionID = filter.Term.ActionID
		}
	}
	if err, ok := b.errs[actionID]; ok {
		return nil, err
	}
	hits := b.hits[actionID]
	if got.Size > 0 && len(hits) > got.Size {
		hits = hits[:got.Size]
	}
	if len(got.Source.Includes) > 0 {
		filtered := make([]es.HitT, len(hits))
		for i, hit := range hits {
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(hit.Source, &doc); err != nil {
				return nil, err
			}
			kept := make(map[string]json.RawMessage, len(got.Source.Includes))
			for _, field := range got.Source.Includes {
				if v, ok := doc[field]; ok {
					kept[field] = v
				}
			}
			src, err := json.Marshal(kept)
			if err != nil {
				return nil, err
			}
			hit.Source = src
			filtered[i] = hit
		}
		hits = filtered
	}
	res := &es.ResultT{Hits: hits}
	return res, nil
}

func TestFindAction(t *testing.T) {
	bulker := &fakeActionSearchBulk{
		hits: map[string][]es.HitT{
			"action-1": {
				{ID: "doc-1", Source: actionSource("action-1", "00-trace-span-01", "agent-1")},
			},
			"split-action": {
				{ID: "doc-split-1", Source: actionSource("split-action", "00-trace-span-02", "agent-1")},
				{ID: "doc-split-2", Source: actionSource("split-action", "00-trace-span-02", "agent-2")},
			},
		},
		errs: map[string]error{
			"missing-index-action": es.ErrIndexNotFound,
			"timed-out-action":     es.ErrTimeout,
		},
	}

	tests := []struct {
		name       string
		actionID   string
		wantAction model.Action
		wantErr    error
	}{
		{
			name:     "the action metadata that the search finds is returned without payload fields",
			actionID: "action-1",
			wantAction: model.Action{
				ESDocument:  model.ESDocument{Id: "doc-1"},
				ActionID:    "action-1",
				Type:        "UPGRADE",
				Namespaces:  []string{"default"},
				Traceparent: "00-trace-span-01",
			},
		},
		{
			name:     "a split action returns one hit without payload fields",
			actionID: "split-action",
			wantAction: model.Action{
				ESDocument:  model.ESDocument{Id: "doc-split-1"},
				ActionID:    "split-action",
				Type:        "UPGRADE",
				Namespaces:  []string{"default"},
				Traceparent: "00-trace-span-02",
			},
		},
		{
			name:     "an action that does not exist is not found",
			actionID: "missing-action",
			wantErr:  ErrNotFound,
		},
		{
			name:     "an action is not found when the index does not exist",
			actionID: "missing-index-action",
			wantErr:  ErrNotFound,
		},
		{
			name:     "the error of a failed search is returned",
			actionID: "timed-out-action",
			wantErr:  es.ErrTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, err := FindAction(t.Context(), bulker, tt.actionID)
			if tt.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tt.wantErr)
			}
			assert.Equal(t, tt.wantAction, action)
		})
	}
}

func TestFindActionMultipleHits(t *testing.T) {
	bulker := ftesting.NewMockBulk()
	bulker.On("Search", mock.Anything, FleetActions, mock.Anything, mock.Anything).Return(&es.ResultT{
		Hits: []es.HitT{
			{ID: "doc-1", Source: []byte(`{"action_id":"action-1"}`)},
			{ID: "doc-2", Source: []byte(`{"action_id":"action-1"}`)},
		},
	}, nil)

	action, err := FindAction(t.Context(), bulker, "action-1")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound)
	assert.Empty(t, action)
}

func actionSource(actionID, traceparent, agentID string) []byte {
	src := fmt.Appendf(nil,
		`{"action_id":%q,"type":"UPGRADE","namespaces":["default"],"traceparent":%q,"agents":[%q],"data":{"version":"9.0.0"},"signed":{"data":"c2lnbmVk"}}`,
		actionID, traceparent, agentID,
	)
	return src
}
