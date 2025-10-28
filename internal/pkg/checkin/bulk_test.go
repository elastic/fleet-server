// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package checkin

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"

	"github.com/google/go-cmp/cmp"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Test simple,
// Test with fields
// Test with seq no

// matchOp is used with mock.MatchedBy to match and validate the operation
func matchOp(tb testing.TB, c testcase, ts time.Time) func(ops []bulk.MultiOp) bool {
	return func(ops []bulk.MultiOp) bool {
		if len(ops) != 1 {
			return false
		}
		if ops[0].ID != c.id {
			return false
		}
		if ops[0].Index != dl.FleetAgents {
			return false
		}
		tb.Log("Operation match! validating details...")

		// Decode and match operation
		// NOTE putting the extra validation here seems strange, maybe we should read the args in the test body intstead?
		type updateT struct {
			LastCheckin   string          `json:"last_checkin"`
			Status        string          `json:"last_checkin_status"`
			UpdatedAt     string          `json:"updated_at"`
			AgentPolicyID string          `json:"agent_policy_id,omitempty"`
			RevisionIDX   int64           `json:"policy_revision_idx,omitempty"`
			Meta          json.RawMessage `json:"local_metadata"`
			SeqNo         sqn.SeqNo       `json:"action_seq_no"`
		}

		m := make(map[string]updateT)
		err := json.Unmarshal(ops[0].Body, &m)
		require.NoErrorf(tb, err, "unable to validate operation body %s", string(ops[0].Body))

		sub, ok := m["doc"]
		require.True(tb, ok, "unable to validate operation: expected doc")

		validateTimestamp(tb, ts.Truncate(time.Second), sub.LastCheckin)
		validateTimestamp(tb, ts.Truncate(time.Second), sub.UpdatedAt)
		assert.Equal(tb, c.policyID, sub.AgentPolicyID)
		assert.Equal(tb, c.revisionIDX, sub.RevisionIDX)
		if c.seqno != nil {
			if cdiff := cmp.Diff(c.seqno, sub.SeqNo); cdiff != "" {
				tb.Error(cdiff)
			}
		}

		if c.meta != nil {
			assert.Equal(tb, json.RawMessage(c.meta), sub.Meta)
		}
		assert.Equal(tb, c.status, sub.Status)
		return true
	}
}

type testcase struct {
	name            string
	id              string
	status          string
	message         string
	policyID        string
	revisionIDX     int64
	meta            []byte
	components      []byte
	seqno           sqn.SeqNo
	ver             string
	unhealthyReason *[]string
}

func TestBulkSimple(t *testing.T) {
	start := time.Now()

	const ver = "8.9.0"
	cases := []testcase{{
		name:    "Simple case",
		id:      "simpleId",
		status:  "online",
		message: "message",
	}, {
		name:        "Simple case with policy id and revision idx",
		id:          "simpleId",
		status:      "online",
		message:     "message",
		policyID:    "testPolicy",
		revisionIDX: 1,
	}, {
		name:    "has meta with fips attribute",
		id:      "metaCaseID",
		status:  "online",
		message: "message",
		meta:    []byte(`{"fips":true,"snapshot":false}`),
	}, {
		name:       "Singled field case",
		id:         "singleFieldId",
		status:     "online",
		message:    "message",
		meta:       []byte(`{"hey":"now"}`),
		components: []byte(`[{"id":"winlog-default"}]`),
	}, {
		name:       "Multi field case",
		id:         "multiFieldId",
		status:     "online",
		message:    "message",
		meta:       []byte(`{"hey":"now","brown":"cow"}`),
		components: []byte(`[{"id":"winlog-default","type":"winlog"}]`),
		ver:        ver,
	}, {
		name:       "Multi field nested case",
		id:         "multiFieldNestedId",
		status:     "online",
		message:    "message",
		meta:       []byte(`{"hey":"now","wee":{"little":"doggie"}}`),
		components: []byte(`[{"id":"winlog-default","type":"winlog"}]`),
	}, {
		name:    "Simple case with seqNo",
		id:      "simpleseqno",
		status:  "online",
		message: "message",
		seqno:   sqn.SeqNo{1, 2, 3, 4},
		ver:     ver,
	}, {
		name:       "Field case with seqNo",
		id:         "simpleseqno",
		status:     "online",
		message:    "message",
		meta:       []byte(`{"uncle":"fester"}`),
		components: []byte(`[{"id":"log-default"}]`),
		seqno:      sqn.SeqNo{5, 6, 7, 8},
		ver:        ver,
	}, {
		name:    "Unusual status",
		id:      "singleFieldId",
		status:  "unusual",
		message: "message",
	}, {
		name:    "Empty status",
		id:      "singleFieldId",
		status:  "",
		message: "message",
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := testlog.SetLogger(t).WithContext(t.Context())
			mockBulk := ftesting.NewMockBulk()
			mockBulk.On("MUpdate", mock.Anything, mock.MatchedBy(matchOp(t, c, start)), mock.Anything).Return([]bulk.BulkIndexerResponseItem{}, nil).Once()
			bc := NewBulk(mockBulk)

			opts := []Option{WithStatus(c.status), WithMessage(c.message)}
			if c.policyID != "" {
				opts = append(opts, WithAgentPolicyID(c.policyID), WithPolicyRevisionIDX(c.revisionIDX))
			}
			if c.meta != nil {
				opts = append(opts, WithMeta(c.meta))
			}
			if c.components != nil {
				opts = append(opts, WithComponents(c.components))
			}
			if c.seqno != nil {
				opts = append(opts, WithSeqNo(c.seqno))
			}
			if c.ver != "" {
				opts = append(opts, WithVer(c.ver))
			}
			if c.unhealthyReason != nil {
				opts = append(opts, WithUnhealthyReason(c.unhealthyReason))
			}

			err := bc.CheckIn(c.id, opts...)
			require.NoError(t, err)
			err = bc.flush(ctx)
			require.NoError(t, err)

			mockBulk.AssertExpectations(t)
		})
	}
}

func TestBulkReusePending(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	const (
		agentID = "test-agent-id"
		status  = "online"
		message = "test message"
	)

	meta := []byte(`{"test":"metadata"}`)

	// Matcher that validates both the existing field (status) and new field (meta) are present
	matchAccumulatedOps := func(ops []bulk.MultiOp) bool {
		if len(ops) != 1 {
			t.Errorf("Expected 1 operation, got %d", len(ops))
			return false
		}
		if ops[0].ID != agentID {
			t.Errorf("Expected ID %s, got %s", agentID, ops[0].ID)
			return false
		}

		type updateT struct {
			Status string          `json:"last_checkin_status"`
			Meta   json.RawMessage `json:"local_metadata"`
		}

		m := make(map[string]updateT)
		err := json.Unmarshal(ops[0].Body, &m)
		require.NoErrorf(t, err, "unable to validate operation body %s", string(ops[0].Body))

		sub, ok := m["doc"]
		require.True(t, ok, "unable to validate operation: expected doc")

		assert.Equal(t, status, sub.Status, "Expected status from first CheckIn to be preserved")
		assert.Equal(t, json.RawMessage(meta), sub.Meta, "Expected metadata from second CheckIn to be added")
		return true
	}

	mockBulk := ftesting.NewMockBulk()
	mockBulk.On("MUpdate", mock.Anything, mock.MatchedBy(matchAccumulatedOps), mock.Anything).Return([]bulk.BulkIndexerResponseItem{}, nil).Once()

	bc := NewBulk(mockBulk)

	err := bc.CheckIn(agentID, WithStatus(status), WithMessage(message))
	require.NoError(t, err)
	err = bc.CheckIn(agentID, WithMeta(meta))
	require.NoError(t, err)
	err = bc.flush(ctx)
	require.NoError(t, err)

	mockBulk.AssertExpectations(t)
}

func validateTimestamp(tb testing.TB, start time.Time, ts string) {
	t1, err := time.Parse(time.RFC3339, ts)
	require.NoErrorf(tb, err, "expected %q to be in RFC 3339 format", ts)
	require.False(tb, start.After(t1), "timestamp in the past")
}

func benchmarkBulk(n int, b *testing.B) {
	mockBulk := ftesting.NewMockBulk()
	bc := NewBulk(mockBulk)

	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := xid.New().String()
		ids = append(ids, id)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, id := range ids {
			err := bc.CheckIn(id)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

func benchmarkFlush(n int, b *testing.B) {
	ctx := context.Background()
	mockBulk := ftesting.NewMockBulk()
	mockBulk.On("MUpdate", mock.Anything, mock.Anything, []bulk.Opt(nil)).Return([]bulk.BulkIndexerResponseItem{}, nil)
	bc := NewBulk(mockBulk)

	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := xid.New().String()
		ids = append(ids, id)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		for _, id := range ids {
			err := bc.CheckIn(id) // TODO ths benchmark is not very interesting as the simplecache is used
			if err != nil {
				b.Fatal(err)
			}
		}
		b.StartTimer()

		err := bc.flush(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}

}

func BenchmarkBulk_1(b *testing.B)      { benchmarkBulk(1, b) }
func BenchmarkBulk_64(b *testing.B)     { benchmarkBulk(64, b) }
func BenchmarkBulk_8192(b *testing.B)   { benchmarkBulk(8192, b) }
func BenchmarkBulk_37268(b *testing.B)  { benchmarkBulk(37268, b) }
func BenchmarkBulk_131072(b *testing.B) { benchmarkBulk(131072, b) }
func BenchmarkBulk_262144(b *testing.B) { benchmarkBulk(262144, b) }

func BenchmarkFlush_1(b *testing.B)      { benchmarkFlush(1, b) }
func BenchmarkFlush_64(b *testing.B)     { benchmarkFlush(64, b) }
func BenchmarkFlush_8192(b *testing.B)   { benchmarkFlush(8192, b) }
func BenchmarkFlush_37268(b *testing.B)  { benchmarkFlush(37268, b) }
func BenchmarkFlush_131072(b *testing.B) { benchmarkFlush(131072, b) }
func BenchmarkFlush_262144(b *testing.B) { benchmarkFlush(262144, b) }
