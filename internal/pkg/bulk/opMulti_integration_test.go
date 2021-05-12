// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build integration

package bulk

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// This runs a series of CRUD operations through elastic.
// Not a particularly useful benchmark, but gives some idea of memory overhead.

func benchmarkMultiUpdate(n int, b *testing.B) {
	b.ReportAllocs()
	defer (QuietLogger())()

	l := zerolog.GlobalLevel()
	defer zerolog.SetGlobalLevel(l)

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := SetupIndexWithBulk(ctx, b, testPolicy, WithFlushThresholdCount(n), WithFlushInterval(time.Millisecond*10))

	// Create N samples
	var ops []MultiOp
	for i := 0; i < n; i++ {
		sample := NewRandomSample()
		ops = append(ops, MultiOp{
			Index: index,
			Body:  sample.marshal(b),
		})
	}

	items, err := bulker.MCreate(ctx, ops)
	if err != nil {
		b.Fatal(err)
	}

	for j := 0; j < b.N; j++ {
		fields := UpdateFields{
			"dateval": time.Now().Format(time.RFC3339),
		}

		body, err := fields.Marshal()
		if err != nil {
			b.Fatal(err)
		}

		for i := range ops {
			ops[i].Id = items[i].DocumentID
			ops[i].Body = body
		}

		_, err = bulker.MUpdate(ctx, ops)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMultiUpdate(b *testing.B) {

	benchmarks := []int{1, 64, 8192, 37268, 131072}

	for _, n := range benchmarks {

		bindFunc := func(n int) func(b *testing.B) {
			return func(b *testing.B) {
				benchmarkMultiUpdate(n, b)
			}
		}
		b.Run(strconv.Itoa(n), bindFunc(n))
	}
}
