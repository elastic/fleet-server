// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package policy

import (
	"runtime/metrics"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const (
	memorySamplingInterval = 100 * time.Millisecond
	bytesPerMB             = 1024 * 1024

	metricHeapObjects = "/memory/classes/heap/objects:bytes"
	metricTotalMemory = "/memory/classes/total:bytes"
)

func toMB(bytes uint64) float64 {
	return float64(bytes*10/bytesPerMB) / 10
}

// reloadMetrics measures the duration of a policy reload, of its phases, and the memory of the
// Fleet Server process during the reload. The memory is process wide (checkins and other work
// included) and sampled, so the peak is an indication to compare runs with, not an exact
// allocation of the reload.
//
// It is only created when debug logging is enabled. All methods are safe to call on a nil receiver.
type reloadMetrics struct {
	startedAt   time.Time
	startHeap   uint64
	startTotal  uint64
	peakHeap    uint64
	peakTotal   uint64
	mut         sync.Mutex
	phases      map[string]time.Duration
	stopSampler chan struct{}
	done        chan struct{}
}

// startReloadMetrics returns nil when debug logging is not enabled.
func startReloadMetrics(log zerolog.Logger) *reloadMetrics {
	if !log.Debug().Enabled() {
		return nil
	}
	heap, total := readMemory()
	r := &reloadMetrics{
		startedAt:   time.Now(),
		startHeap:   heap,
		startTotal:  total,
		peakHeap:    heap,
		peakTotal:   total,
		phases:      make(map[string]time.Duration),
		stopSampler: make(chan struct{}),
		done:        make(chan struct{}),
	}
	go r.sample()
	return r
}

func readMemory() (heap uint64, total uint64) {
	samples := []metrics.Sample{{Name: metricHeapObjects}, {Name: metricTotalMemory}}
	metrics.Read(samples)
	if samples[0].Value.Kind() == metrics.KindUint64 {
		heap = samples[0].Value.Uint64()
	}
	if samples[1].Value.Kind() == metrics.KindUint64 {
		total = samples[1].Value.Uint64()
	}
	return heap, total
}

func (r *reloadMetrics) sample() {
	defer close(r.done)
	t := time.NewTicker(memorySamplingInterval)
	defer t.Stop()
	for {
		select {
		case <-r.stopSampler:
			return
		case <-t.C:
			r.sampleMemory()
		}
	}
}

func (r *reloadMetrics) sampleMemory() {
	heap, total := readMemory()
	r.mut.Lock()
	defer r.mut.Unlock()
	r.peakHeap = max(r.peakHeap, heap)
	r.peakTotal = max(r.peakTotal, total)
}

// measure runs fn and adds its duration to the named phase.
func (r *reloadMetrics) measure(name string, fn func() error) error {
	if r == nil {
		return fn()
	}
	start := time.Now()
	err := fn()
	d := time.Since(start)
	r.mut.Lock()
	r.phases[name] += d
	r.mut.Unlock()
	return err
}

// log stops the measurement and logs the result at debug level.
func (r *reloadMetrics) log(log zerolog.Logger, trigger string, nPolicies int) {
	if r == nil {
		return
	}
	close(r.stopSampler)
	<-r.done
	r.sampleMemory()
	endHeap, endTotal := readMemory()

	r.mut.Lock()
	defer r.mut.Unlock()
	phases := zerolog.Dict()
	for name, d := range r.phases {
		phases.Int64(name, d.Milliseconds())
	}
	log.Debug().
		Str("trigger", trigger).
		Int("nPolicies", nPolicies).
		Int64("durationMs", time.Since(r.startedAt).Milliseconds()).
		Dict("phaseDurationsMs", phases).
		Float64("heapUsedMbAtStart", toMB(r.startHeap)).
		Float64("heapUsedMbAtEnd", toMB(endHeap)).
		Float64("heapUsedMbPeak", toMB(r.peakHeap)).
		Float64("heapUsedMbPeakIncrease", toMB(r.peakHeap-r.startHeap)).
		Float64("totalMemoryMbAtStart", toMB(r.startTotal)).
		Float64("totalMemoryMbAtEnd", toMB(endTotal)).
		Float64("totalMemoryMbPeak", toMB(r.peakTotal)).
		Msg("Policy reload metrics")
}
