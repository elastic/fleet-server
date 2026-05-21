// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newStreamCheckinT returns a minimal CheckinT with only bc populated, which is
// all that streamParseCheckinRequest / streamComponentsArray use.
func newStreamCheckinT() *CheckinT {
	return &CheckinT{
		// CheckIn only locks a mutex and writes to the pending map, so a
		// nil bulker is fine for unit tests that never call Run/flush.
		bc: checkin.NewBulk(nil),
	}
}

// newTestAgent returns a minimal Agent suitable for streaming-parse tests.
func newTestAgent(id string) *model.Agent {
	a := &model.Agent{}
	a.Id = id
	return a
}

// makeComponents returns a JSON array string of n minimal component objects.
func makeComponents(n int) string {
	elems := make([]string, n)
	for i := range elems {
		elems[i] = fmt.Sprintf(`{"id":"comp-%d","status":"online","message":"ok","units":[]}`, i)
	}
	return "[" + strings.Join(elems, ",") + "]"
}

// makeUnhealthyComponents returns a JSON array of n components all with FAILED
// status and one input unit, so calcUnhealthyReason returns ["input"].
func makeUnhealthyComponents(n int) string {
	elems := make([]string, n)
	for i := range elems {
		elems[i] = fmt.Sprintf(
			`{"id":"comp-%d","status":"FAILED","message":"bad","units":[{"id":"u-%d","type":"input","status":"FAILED","message":"err"}]}`,
			i, i,
		)
	}
	return "[" + strings.Join(elems, ",") + "]"
}

func TestStreamParseCheckinRequest_BasicFields(t *testing.T) {
	ct := newStreamCheckinT()
	body := `{
		"status": "online",
		"message": "running",
		"ack_token": "tok123",
		"poll_timeout": "30s"
	}`

	req, reason, err := ct.streamParseCheckinRequest(strings.NewReader(body), componentFlushThreshold, newTestAgent("a1"))
	require.NoError(t, err)

	assert.Equal(t, CheckinRequestStatus("online"), req.Status)
	assert.Equal(t, "running", req.Message)
	require.NotNil(t, req.AckToken)
	assert.Equal(t, "tok123", *req.AckToken)
	require.NotNil(t, req.PollTimeout)
	assert.Equal(t, "30s", *req.PollTimeout)
	assert.Nil(t, reason, "no components means nil reason")
}

func TestStreamParseCheckinRequest_NoComponents(t *testing.T) {
	ct := newStreamCheckinT()
	body := `{"status":"online","message":"ok"}`

	_, reason, err := ct.streamParseCheckinRequest(strings.NewReader(body), componentFlushThreshold, newTestAgent("a1"))
	require.NoError(t, err)
	assert.Nil(t, reason)
}

func TestStreamParseCheckinRequest_ComponentsHealthy(t *testing.T) {
	ct := newStreamCheckinT()
	comps := makeComponents(3)
	body := fmt.Sprintf(`{"status":"online","message":"ok","components":%s}`, comps)

	_, reason, err := ct.streamParseCheckinRequest(strings.NewReader(body), componentFlushThreshold, newTestAgent("a1"))
	require.NoError(t, err)
	// All components are healthy: calcUnhealthyReason returns an empty slice.
	// The pointer is non-nil because we appended to reason.
	require.NotNil(t, reason)
	assert.Empty(t, *reason)
}

func TestStreamParseCheckinRequest_ComponentsUnhealthy(t *testing.T) {
	ct := newStreamCheckinT()
	comps := makeUnhealthyComponents(2)
	body := fmt.Sprintf(`{"status":"online","message":"ok","components":%s}`, comps)

	_, reason, err := ct.streamParseCheckinRequest(strings.NewReader(body), componentFlushThreshold, newTestAgent("a1"))
	require.NoError(t, err)
	require.NotNil(t, reason)
	assert.Equal(t, []string{"input"}, *reason)
}

func TestStreamParseCheckinRequest_ComponentsAboveThreshold(t *testing.T) {
	ct := newStreamCheckinT()
	// threshold=1 forces a flush after every element
	comps := makeComponents(5)
	body := fmt.Sprintf(`{"status":"online","message":"ok","components":%s}`, comps)

	_, _, err := ct.streamParseCheckinRequest(strings.NewReader(body), 1, newTestAgent("a1"))
	require.NoError(t, err)
}

func TestStreamParseCheckinRequest_ComponentsNullValue(t *testing.T) {
	ct := newStreamCheckinT()
	body := `{"status":"online","message":"ok","components":null}`

	_, reason, err := ct.streamParseCheckinRequest(strings.NewReader(body), componentFlushThreshold, newTestAgent("a1"))
	require.NoError(t, err)
	assert.Nil(t, reason)
}

func TestStreamParseCheckinRequest_ComponentsEmptyArray(t *testing.T) {
	ct := newStreamCheckinT()
	body := `{"status":"online","message":"ok","components":[]}`

	_, reason, err := ct.streamParseCheckinRequest(strings.NewReader(body), componentFlushThreshold, newTestAgent("a1"))
	require.NoError(t, err)
	assert.Nil(t, reason)
}

func TestStreamParseCheckinRequest_ComponentsBadShape(t *testing.T) {
	ct := newStreamCheckinT()
	// The components array contains a string instead of an object — should error.
	body := `{"status":"online","message":"ok","components":["not-an-object"]}`

	_, _, err := ct.streamParseCheckinRequest(strings.NewReader(body), componentFlushThreshold, newTestAgent("a1"))
	require.Error(t, err)
}

func TestStreamParseCheckinRequest_LocalMetadata(t *testing.T) {
	ct := newStreamCheckinT()
	body := `{"status":"online","message":"ok","local_metadata":{"host":"myhost"}}`

	req, _, err := ct.streamParseCheckinRequest(strings.NewReader(body), componentFlushThreshold, newTestAgent("a1"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"host":"myhost"}`, string(req.LocalMetadata))
}

func TestStreamParseCheckinRequest_PolicyRevisionIdx(t *testing.T) {
	ct := newStreamCheckinT()
	body := `{"status":"online","message":"ok","policy_revision_idx":42}`

	req, _, err := ct.streamParseCheckinRequest(strings.NewReader(body), componentFlushThreshold, newTestAgent("a1"))
	require.NoError(t, err)
	require.NotNil(t, req.PolicyRevisionIdx)
	assert.Equal(t, int64(42), *req.PolicyRevisionIdx)
}

func TestStreamParseCheckinRequest_InvalidJSON(t *testing.T) {
	ct := newStreamCheckinT()
	_, _, err := ct.streamParseCheckinRequest(strings.NewReader(`not json`), componentFlushThreshold, newTestAgent("a1"))
	require.Error(t, err)
}

func TestStreamParseCheckinRequest_MultipleFlushesAggregateReason(t *testing.T) {
	ct := newStreamCheckinT()
	// Two unhealthy components, threshold=1 forces a flush after each one.
	// The reason across both batches should still be ["input"].
	comps := makeUnhealthyComponents(2)
	body := fmt.Sprintf(`{"status":"online","message":"ok","components":%s}`, comps)

	_, reason, err := ct.streamParseCheckinRequest(strings.NewReader(body), 1, newTestAgent("a1"))
	require.NoError(t, err)
	require.NotNil(t, reason)
	assert.Equal(t, []string{"input", "input"}, *reason)
}
