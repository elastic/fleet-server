// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/action"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
)

func BenchmarkCheckinLongPollMemory(b *testing.B) {
	const polls = 1000
	body, agentDoc := benchCheckinPayloads()
	zlog := zerolog.Nop()

	var total, iterations int64
	for b.Loop() {
		bulker := &benchSearchBulk{polls: polls, ready: make(chan struct{})}
		ct := newBenchCheckinT(b, bulker)
		ctx, cancel := context.WithCancel(b.Context())
		errs := make(chan error, polls)

		before := benchLiveBytes()
		var handlers sync.WaitGroup
		for i := range polls {
			handlers.Go(func() {
				var agent model.Agent
				if err := json.Unmarshal(agentDoc, &agent); err != nil {
					errs <- err
					return
				}
				agent.Id = strconv.Itoa(i)
				// Call the handler without a network connection because TLS clients in this process
				// add their own memory to the measurement.
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/fleet/agents/"+agent.Id+"/checkin", bytes.NewReader(body))
				if err := ct.ProcessRequest(zlog, httptest.NewRecorder(), req, time.Now(), &agent, ""); err != nil {
					errs <- err
				}
			})
		}
		// Each check-in searches for pending actions as the last step before
		// its long poll.
		select {
		case <-bulker.ready:
		case err := <-errs:
			cancel()
			handlers.Wait()
			b.Fatal(err)
		}
		total += (benchLiveBytes() - before) / polls
		iterations++

		cancel()
		handlers.Wait()
		close(errs)
		if err := <-errs; err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(total/iterations), "bytes/longpoll")
}

func newBenchCheckinT(b *testing.B, bulker *benchSearchBulk) *CheckinT {
	b.Helper()
	cfg := &config.Server{}
	cfg.InitDefaults()
	cfg.Timeouts.CheckinLongPoll = time.Hour
	cfg.Timeouts.CheckinTimestamp = time.Hour
	cfg.Timeouts.CheckinJitter = 0
	cfg.Limits.CheckinLimit.MaxBody = 1024 * 1024

	ct, err := NewCheckinT(mustBuildConstraints("8.0.0"), cfg, nil, checkin.NewBulk(bulker),
		benchPolicyMonitor{}, benchCheckpoint{}, action.NewDispatcher(nil, 0, 1, bulker), bulker)
	if err != nil {
		b.Fatal(err)
	}
	return ct
}

// benchLiveBytes returns the live heap plus the goroutine stacks after a full GC.
func benchLiveBytes() int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc + m.StackInuse) //nolint:gosec // a heap size is far below MaxInt64
}

// benchCheckinPayloads returns a check-in body of about 10 KB and the agent
// document that Elasticsearch stores after that check-in.
func benchCheckinPayloads() (body, agentDoc []byte) {
	components := make([]string, 0, 40)
	for i := range 40 {
		components = append(components, fmt.Sprintf(`{"id":"component-%d","type":"filestream","status":"HEALTHY","message":"Healthy","units":[{"id":"component-%d-input","type":"input","status":"HEALTHY","message":"Healthy"},{"id":"component-%d-output","type":"output","status":"HEALTHY","message":"Healthy"}]}`, i, i, i))
	}
	comps := "[" + strings.Join(components, ",") + "]"
	meta := `{"elastic":{"agent":{"id":"benchmark-agent","version":"8.0.0"}},"host":{"hostname":"benchmark-host"}}`
	body = fmt.Appendf(nil, `{"status":"online","message":"Running","agent_policy_id":"benchmark-policy","policy_revision_idx":1,"local_metadata":%s,"components":%s}`, meta, comps)
	agentDoc = fmt.Appendf(nil, `{"active":true,"agent":{"id":"benchmark-agent","version":"8.0.0"},"policy_id":"benchmark-policy","agent_policy_id":"benchmark-policy","policy_revision_idx":1,"local_metadata":%s,"components":%s}`, meta, comps)
	return body, agentDoc
}

// benchSearchBulk answers searches with no hits. Unlike the mock bulker, it
// keeps no history of calls, which would add memory to each check-in.
type benchSearchBulk struct {
	bulk.Bulk
	polls    int64
	searches atomic.Int64
	ready    chan struct{}
}

func (b *benchSearchBulk) Search(context.Context, string, []byte, ...bulk.Opt) (*es.ResultT, error) {
	if b.searches.Add(1) == b.polls {
		close(b.ready)
	}
	return &es.ResultT{}, nil
}

func (b *benchSearchBulk) HasTracer() bool { return false }

var errBenchNoPolicy = errors.New("benchmark has no policy")

// benchPolicyMonitor never sends a policy so that each check-in long polls.
type benchPolicyMonitor struct{}

func (benchPolicyMonitor) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (benchPolicyMonitor) Subscribe(agentID, policyID string, revIdx int64) (policy.Subscription, error) {
	return policy.NewSub(policyID, agentID, revIdx), nil
}

func (benchPolicyMonitor) Unsubscribe(policy.Subscription) error { return nil }

func (benchPolicyMonitor) LatestRev(context.Context, string) int64 { return 0 }

func (benchPolicyMonitor) GetPolicy(context.Context, string) (*model.Policy, error) {
	return nil, errBenchNoPolicy
}

type benchCheckpoint struct{}

func (benchCheckpoint) GetCheckpoint() sqn.SeqNo { return sqn.DefaultSeqNo }
