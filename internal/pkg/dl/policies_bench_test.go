// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"runtime"
	"runtime/metrics"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
)

const (
	benchSpace     = "space-a"
	benchOutput    = "primary"
	benchTimestamp = "2026-01-01T00:00:00.000Z"
	benchOsquery   = "osquery"

	benchNamespace = "namespace"
	benchVersion   = "version"
	benchDataset   = "dataset"
	benchField     = "field"
	benchES        = "elasticsearch"
	benchLogs      = "logs"
	benchHosts     = "hosts"
)

type benchQuery struct {
	Query      string                       `json:"query"`
	ScheduleID string                       `json:"schedule_id"`
	StartDate  string                       `json:"start_date"`
	SpaceID    string                       `json:"space_id"`
	Interval   int                          `json:"interval"`
	Platform   string                       `json:"platform,omitempty"`
	Version    string                       `json:"version,omitempty"`
	EcsMapping map[string]map[string]string `json:"ecs_mapping,omitempty"`
}

type benchPack struct {
	Shard   int                   `json:"shard"`
	PackID  string                `json:"pack_id"`
	Name    string                `json:"pack_name"`
	SpaceID string                `json:"default_space_id"`
	Queries map[string]benchQuery `json:"queries"`
}

type benchOsqueryConfig struct {
	Options map[string]bool      `json:"options"`
	Packs   map[string]benchPack `json:"packs"`
}

type benchStream struct {
	ID         string            `json:"id"`
	DataStream map[string]string `json:"data_stream"`
	Paths      []string          `json:"paths"`
	Processors []map[string]any  `json:"processors"`
}

type benchInput struct {
	ID              string              `json:"id"`
	Revision        int                 `json:"revision"`
	Name            string              `json:"name"`
	Type            string              `json:"type"`
	UseOutput       string              `json:"use_output"`
	PackagePolicyID string              `json:"package_policy_id"`
	DataStream      map[string]string   `json:"data_stream"`
	Meta            map[string]any      `json:"meta,omitempty"`
	Streams         []benchStream       `json:"streams,omitempty"`
	Osquery         *benchOsqueryConfig `json:"osquery,omitempty"`
}

type benchData struct {
	ID                string                    `json:"id"`
	Revision          int                       `json:"revision"`
	Outputs           map[string]map[string]any `json:"outputs"`
	Agent             map[string]any            `json:"agent"`
	Fleet             map[string]any            `json:"fleet"`
	Inputs            []benchInput              `json:"inputs"`
	OutputPermissions map[string]map[string]any `json:"output_permissions"`
	SecretReferences  []any                     `json:"secret_references"`
}

type benchPolicy struct {
	Timestamp   string    `json:"@timestamp"`
	PolicyID    string    `json:"policy_id"`
	RevisionIdx int       `json:"revision_idx"`
	Namespaces  []string  `json:"namespaces"`
	Data        benchData `json:"data"`
}

// searchOnlyBulk answers Search with the given policy documents; any other method panics (nil
// embedded interface). Like a real Elasticsearch response, every Search call materializes a new
// copy of the documents, so the raw JSON that exists while a load is decoded is part of the heap
// that the benchmark measures.
type searchOnlyBulk struct {
	bulk.Bulk
	docs [][]byte
}

func (b searchOnlyBulk) Search(context.Context, string, []byte, ...bulk.Opt) (*es.ResultT, error) {
	return freshResult(b.docs), nil
}

var queryVocab = strings.Fields(`SELECT FROM WHERE AND OR JOIN LEFT ON name path pid uid gid cmdline
	processes file hash sha256 users groups process_open_files listening_ports mounts last time
	datetime unixepoch LIKE IN NOT NULL LIMIT ORDER BY GROUP COUNT CASE WHEN THEN ELSE END`)

func randomQuery(r *rand.Rand, size int) string {
	var sb strings.Builder
	for sb.Len() < size {
		sb.WriteString(queryVocab[r.Intn(len(queryVocab))])
		sb.WriteByte(' ')
	}
	return sb.String()
}

// syntheticPolicies builds policy documents shaped like a large osquery-heavy deployment:
// every policy repeats the same set of integration inputs and, for most of them, the same
// few hundred osquery pack queries (about 70% short, a few several KB long). Identifiers that
// are unique per policy (package policy ids, schedule ids) are kept unique so that they cannot
// be shared.
func syntheticPolicies(numPolicies int) [][]byte {
	r := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic benchmark data
	const distinctQueries = 300
	queries := make([]string, distinctQueries)
	for i := range queries {
		var size int
		switch p := r.Intn(100); {
		case p < 70:
			size = 20 + r.Intn(380)
		case p < 95:
			size = 400 + r.Intn(2600)
		default:
			size = 3000 + r.Intn(6500)
		}
		queries[i] = randomQuery(r, size)
	}
	inputTypes := []string{"logfile", "journald", "winlog", "filestream", "aws-s3", "cel", "httpjson", "udp"}

	docs := make([][]byte, 0, numPolicies)
	for p := 0; p < numPolicies; p++ {
		inputs := make([]benchInput, 0, 16)
		for i := 0; i < 8; i++ {
			typ := inputTypes[i%len(inputTypes)]
			dataset := "integration." + typ
			inputs = append(inputs, benchInput{
				ID:              fmt.Sprintf("%s-%d-%d", typ, p, i),
				Revision:        1,
				Name:            fmt.Sprintf("integration-%d", i),
				Type:            typ,
				UseOutput:       benchOutput,
				PackagePolicyID: fmt.Sprintf("00000000-0000-4000-8000-%04d%08d", p, i),
				DataStream:      map[string]string{benchNamespace: benchSpace},
				Meta:            map[string]any{"package": map[string]any{"name": "integration-" + typ, benchVersion: "1.2.3"}},
				Streams: []benchStream{{
					ID:         fmt.Sprintf("%s-stream-%d-%d", typ, p, i),
					DataStream: map[string]string{benchDataset: dataset, FiledType: benchLogs},
					Paths:      []string{"/var/log/messages", "/var/log/syslog"},
					Processors: []map[string]any{{"add_fields": map[string]any{
						"target": "event", "fields": map[string]any{benchDataset: dataset},
					}}},
				}},
			})
		}
		if p%4 != 3 { // 75% of the policies carry the osquery pack
			packs := map[string]benchPack{}
			for k := 0; k < 4; k++ {
				qs := map[string]benchQuery{}
				n := 40 + r.Intn(40)
				for q := 0; q < n; q++ {
					idx := (k*70 + q) % distinctQueries
					entry := benchQuery{
						Query:      queries[idx],
						ScheduleID: fmt.Sprintf("%08d-%04d-4000-8000-%012d", p, k*100+q, r.Int63n(1_000_000_000_000)),
						StartDate:  benchTimestamp,
						SpaceID:    benchSpace,
						Interval:   3600,
					}
					if q%3 != 0 {
						entry.Platform = "linux,darwin"
						entry.Version = "5.0.0"
					}
					if q%5 == 0 {
						entry.EcsMapping = map[string]map[string]string{
							"process.pid":        {benchField: "pid"},
							"process.executable": {benchField: "path"},
						}
					}
					qs[fmt.Sprintf("query_%d_%d", k, idx)] = entry
				}
				packs[fmt.Sprintf("pack-%d", k)] = benchPack{
					Shard: 100, PackID: fmt.Sprintf("pack-%d", k), Name: fmt.Sprintf("pack %d", k),
					SpaceID: benchSpace, Queries: qs,
				}
			}
			inputs = append(inputs, benchInput{
				ID: fmt.Sprintf("osquery-%d", p), Revision: 1, Name: "osquery_manager-1", Type: benchOsquery,
				UseOutput: benchOutput, PackagePolicyID: fmt.Sprintf("11111111-0000-4000-8000-%012d", p),
				DataStream: map[string]string{benchNamespace: benchSpace},
				Osquery:    &benchOsqueryConfig{Options: map[string]bool{"disable_distributed": false}, Packs: packs},
			})
		}
		doc := benchPolicy{
			Timestamp:   benchTimestamp,
			PolicyID:    fmt.Sprintf("policy-%d", p),
			RevisionIdx: 1 + p%7,
			Namespaces:  []string{benchSpace},
			Data: benchData{
				ID:       fmt.Sprintf("policy-%d", p),
				Revision: 1 + p%7,
				Outputs: map[string]map[string]any{benchOutput: {
					FiledType: benchES, benchHosts: []any{"https://es.example.test:443"},
				}},
				Agent:             map[string]any{"monitoring": map[string]any{"enabled": true}},
				Fleet:             map[string]any{benchHosts: []any{"https://fleet.example.test:443"}},
				Inputs:            inputs,
				OutputPermissions: map[string]map[string]any{benchOutput: {}},
				SecretReferences:  []any{},
			},
		}
		b, err := json.Marshal(doc)
		if err != nil {
			panic(err)
		}
		docs = append(docs, b)
	}
	return docs
}

// freshResult builds the search result for docs, copying each document as an Elasticsearch
// response would hold its own copy of the hit sources.
func freshResult(docs [][]byte) *es.ResultT {
	buckets := make([]es.Bucket, len(docs))
	for i, d := range docs {
		buckets[i] = es.Bucket{
			Key: fmt.Sprintf("policy-%d", i),
			Aggregations: map[string]es.HitsT{
				FieldRevisionIdx: {Hits: []es.HitT{{ID: fmt.Sprintf("doc-%d", i), Source: bytes.Clone(d)}}},
			},
		}
	}
	return &es.ResultT{Aggregations: map[string]es.Aggregation{FieldPolicyID: {Buckets: buckets}}}
}

func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// peakHeapDuring runs fn and returns the highest heap size (live objects plus garbage not yet
// collected) seen by a sampler that reads it every 50 microseconds while fn runs. The value is
// a lower bound of the true peak, since the heap can briefly exceed it between two samples.
func peakHeapDuring(fn func()) uint64 {
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		for {
			select {
			case <-stop:
				return
			default:
			}
			metrics.Read(sample)
			if v := sample[0].Value.Uint64(); v > peak.Load() {
				peak.Store(v)
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()
	fn()
	close(stop)
	<-done
	return peak.Load()
}

// BenchmarkQueryLatestPolicies decodes a full set of 100 policies (about 19 MB of JSON) the way the
// policy monitor does on every load. Besides time and allocations it reports two memory figures:
//   - retained-MB: the heap the decoded policies keep alive. The policy monitor holds them for as
//     long as they are the latest revision, so this is the steady-state cost.
//   - peak-MB: the highest total heap used by policy data while reloading, i.e. the previous
//     load (still held by the monitor while the new one is decoded) plus the Elasticsearch
//     response, the new load and any garbage produced on the way. This is the figure that matters
//     for the container memory limit.
//
// Both are measured on top of the heap before any policy was loaded. retained-MB is exact;
// peak-MB is sampled (see peakHeapDuring).
func BenchmarkQueryLatestPolicies(b *testing.B) {
	docs := syntheticPolicies(100)
	var rawBytes int
	for _, d := range docs {
		rawBytes += len(d)
	}
	bulker := searchOnlyBulk{docs: docs}
	ctx := context.Background()

	before := heapInUse()
	policies, err := QueryLatestPolicies(ctx, bulker)
	require.NoError(b, err)
	require.Len(b, policies, len(docs))
	retained := heapInUse() - before

	// Reload while the first result is still held, as the policy monitor does. Take the highest
	// of a few reloads because a single sampled run can miss the peak.
	var peak uint64
	for i := 0; i < 5; i++ {
		heapInUse() // collect the garbage left by the previous reload so each run starts clean
		p := peakHeapDuring(func() {
			reloaded, err := QueryLatestPolicies(ctx, bulker)
			if err != nil || len(reloaded) != len(docs) {
				b.Fatalf("unexpected result: %d policies, err=%v", len(reloaded), err)
			}
		})
		peak = max(peak, p-before)
	}
	runtime.KeepAlive(policies)

	b.ReportAllocs()
	b.SetBytes(int64(rawBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := QueryLatestPolicies(ctx, bulker)
		if err != nil || len(got) != len(docs) {
			b.Fatalf("unexpected result: %d policies, err=%v", len(got), err)
		}
	}
	b.StopTimer()
	// Reported last because ResetTimer deletes metrics reported before it.
	b.ReportMetric(float64(retained)/1e6, "retained-MB")
	b.ReportMetric(float64(peak)/1e6, "peak-MB")
}
