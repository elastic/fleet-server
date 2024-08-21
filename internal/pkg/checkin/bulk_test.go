// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package checkin

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/esutil"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"

	"github.com/google/go-cmp/cmp"
	"github.com/rs/xid"
	"github.com/stretchr/testify/mock"
)

// Test simple,
// Test with fields
// Test with seq no

// matchOp is used with mock.MatchedBy to match and validate the operation
func matchOp(tb testing.TB, c bulkcase, ts time.Time) func(ops []bulk.MultiOp) bool {
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
			LastCheckin string          `json:"last_checkin"`
			Status      string          `json:"last_checkin_status"`
			UpdatedAt   string          `json:"updated_at"`
			Meta        json.RawMessage `json:"local_metadata"`
			SeqNo       sqn.SeqNo       `json:"action_seq_no"`
		}

		m := make(map[string]updateT)
		if err := json.Unmarshal(ops[0].Body, &m); err != nil {
			tb.Fatalf("unable to validate operation: %v", err)
		}

		sub, ok := m["doc"]
		if !ok {
			tb.Fatal("unable to validate operation: expected doc")
		}
		validateTimestamp(tb, ts.Truncate(time.Second), sub.LastCheckin)
		validateTimestamp(tb, ts.Truncate(time.Second), sub.UpdatedAt)
		if c.seqno != nil {
			if cdiff := cmp.Diff(c.seqno, sub.SeqNo); cdiff != "" {
				tb.Error(cdiff)
			}
		}

		if c.meta != nil && !bytes.Equal(c.meta, sub.Meta) {
			tb.Error("meta doesn't match up")
		}

		if c.status != sub.Status {
			tb.Error("status mismatch")
		}

		return true
	}
}

type bulkcase struct {
	desc            string
	id              string
	status          string
	message         string
	meta            []byte
	components      []byte
	seqno           sqn.SeqNo
	ver             string
	unhealthyReason *[]string
}

func TestBulkSimple(t *testing.T) {
	start := time.Now()

	const ver = "8.9.0"
	cases := []bulkcase{
		{
			"Simple case",
			"simpleId",
			"online",
			"message",
			nil,
			nil,
			nil,
			"",
			nil,
		},
		{
			"Singled field case",
			"singleFieldId",
			"online",
			"message",
			[]byte(`{"hey":"now"}`),
			[]byte(`[{"id":"winlog-default"}]`),
			nil,
			"",
			nil,
		},
		{
			"Multi field case",
			"multiFieldId",
			"online",
			"message",
			[]byte(`{"hey":"now","brown":"cow"}`),
			[]byte(`[{"id":"winlog-default","type":"winlog"}]`),
			nil,
			ver,
			nil,
		},
		{
			"Multi field nested case",
			"multiFieldNestedId",
			"online",
			"message",
			[]byte(`{"hey":"now","wee":{"little":"doggie"}}`),
			[]byte(`[{"id":"winlog-default","type":"winlog"}]`),
			nil,
			"",
			nil,
		},
		{
			"Simple case with seqNo",
			"simpleseqno",
			"online",
			"message",
			nil,
			nil,
			sqn.SeqNo{1, 2, 3, 4},
			ver,
			nil,
		},
		{
			"Field case with seqNo",
			"simpleseqno",
			"online",
			"message",
			[]byte(`{"uncle":"fester"}`),
			[]byte(`[{"id":"log-default"}]`),
			sqn.SeqNo{5, 6, 7, 8},
			ver,
			nil,
		},
		{
			"Unusual status",
			"singleFieldId",
			"unusual",
			"message",
			nil,
			nil,
			nil,
			"",
			nil,
		},
		{
			"Empty status",
			"singleFieldId",
			"",
			"message",
			nil,
			nil,
			nil,
			"",
			nil,
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			ctx := testlog.SetLogger(t).WithContext(context.Background())
			mockBulk := ftesting.NewMockBulk()
			mockBulk.On("MUpdate", mock.Anything, mock.MatchedBy(matchOp(t, c, start)), mock.Anything).Return([]bulk.BulkIndexerResponseItem{}, nil).Once()
			mockEsClient, _ := esutil.MockESClient(t)
			mockBulk.On("Client").Return(mockEsClient).Once()
			bc := NewBulk(mockBulk)

			if err := bc.CheckIn(c.id, c.status, c.message, c.meta, c.components, c.seqno, c.ver, c.unhealthyReason); err != nil {
				t.Fatal(err)
			}

			if err := bc.flush(ctx); err != nil {
				t.Fatal(err)
			}

			mockBulk.AssertExpectations(t)
		})
	}
}

func validateTimestamp(tb testing.TB, start time.Time, ts string) {
	if t1, err := time.Parse(time.RFC3339, ts); err != nil {
		tb.Error("expected rfc3999")
	} else if start.After(t1) {
		tb.Error("timestamp in the past")
	}
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
			err := bc.CheckIn(id, "", "", nil, nil, nil, "", nil)
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
	mockEsClient, _ := esutil.MockESClient(b)
	mockBulk.On("Client").Return(mockEsClient)
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
			err := bc.CheckIn(id, "", "", nil, nil, nil, "", nil)
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
