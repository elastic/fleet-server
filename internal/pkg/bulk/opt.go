// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"strconv"
	"time"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
)

//-----
// Transaction options

type optionsT struct {
	Refresh            bool
	RetryOnConflict    string
	Indices            []string
	WaitForCheckpoints []int64
}

type Opt func(*optionsT)

func WithRefresh() Opt {
	return func(opt *optionsT) {
		opt.Refresh = true
	}
}

func WithRetryOnConflict(n int) Opt {
	return func(opt *optionsT) {
		opt.RetryOnConflict = strconv.Itoa(n)
	}
}

// WithIndex sets the index when searching
func WithIndex(idx string) Opt {
	return func(opt *optionsT) {
		opt.Indices = append(opt.Indices, idx)
	}
}

// WithWaitForCheckpoints will set the checkpoints parameters
// Applicable to _fleet_msearch, wait_for_checkpoints parameters
func WithWaitForCheckpoints(checkpoints []int64) Opt {
	return func(opt *optionsT) {
		opt.WaitForCheckpoints = checkpoints
	}
}

//-----
// Bulk API options

type bulkOptT struct {
	flushInterval     time.Duration
	flushThresholdCnt int
	flushThresholdSz  int
	maxPending        int
	blockQueueSz      int
	apikeyMaxParallel int
	apikeyMaxReqSize  int
}

type BulkOpt func(*bulkOptT)

// WithFlushInterval sets the interval on which any pending transactions will be flushed to bulker
func WithFlushInterval(d time.Duration) BulkOpt {
	return func(opt *bulkOptT) {
		opt.flushInterval = d
	}
}

// WithFlushThresholdCount sets count of pending transactions that will force flush before interval
func WithFlushThresholdCount(cnt int) BulkOpt {
	return func(opt *bulkOptT) {
		opt.flushThresholdCnt = cnt
	}
}

// WithFlushThresholdSize sets the cummulative size in bytes of pending transactions that will force flush before interval
func WithFlushThresholdSize(sz int) BulkOpt {
	return func(opt *bulkOptT) {
		opt.flushThresholdSz = sz
	}
}

// WithMaxPending sets the number of elastic transactions pending response
func WithMaxPending(max int) BulkOpt {
	return func(opt *bulkOptT) {
		opt.maxPending = max
	}
}

// WithBlockQueueSize sets the size of the internal block queue (ie. channel)
func WithBlockQueueSize(sz int) BulkOpt {
	return func(opt *bulkOptT) {
		opt.blockQueueSz = sz
	}
}

// WithAPIKeyMaxParallel sets the number of api key operations outstanding
func WithAPIKeyMaxParallel(max int) BulkOpt {
	return func(opt *bulkOptT) {
		opt.apikeyMaxParallel = max
	}
}

// WithAPIKeyMaxRequestSize sets the size of the request body. Default 100MB
func WithAPIKeyMaxRequestSize(maxBytes int) BulkOpt {
	return func(opt *bulkOptT) {
		if opt.apikeyMaxReqSize > 0 {
			opt.apikeyMaxReqSize = maxBytes
		}
	}
}

func parseBulkOpts(opts ...BulkOpt) bulkOptT {
	bopt := bulkOptT{
		flushInterval:     defaultFlushInterval,
		flushThresholdCnt: defaultFlushThresholdCnt,
		flushThresholdSz:  defaultFlushThresholdSz,
		maxPending:        defaultMaxPending,
		apikeyMaxParallel: defaultAPIKeyMaxParallel,
		blockQueueSz:      defaultBlockQueueSz,
		apikeyMaxReqSize:  defaultApikeyMaxReqSize,
	}

	for _, f := range opts {
		f(&bopt)
	}

	return bopt
}

func (o *bulkOptT) MarshalZerologObject(e *zerolog.Event) {
	e.Dur("flushInterval", o.flushInterval)
	e.Int("flushThresholdCnt", o.flushThresholdCnt)
	e.Int("flushThresholdSz", o.flushThresholdSz)
	e.Int("maxPending", o.maxPending)
	e.Int("blockQueueSz", o.blockQueueSz)
	e.Int("apikeyMaxParallel", o.apikeyMaxParallel)
	e.Int("apikeyMaxReqSize", o.apikeyMaxReqSize)
}

// BulkOptsFromCfg transforms config to a slize of BulkOpt
// used to bridge to configuration subsystem
func BulkOptsFromCfg(cfg *config.Config) []BulkOpt {

	bulkCfg := cfg.Inputs[0].Server.Bulk

	// Attempt to slice the max number of connections to leave room for the bulk flush queues
	maxKeyParallel := cfg.Output.Elasticsearch.MaxConnPerHost
	if cfg.Output.Elasticsearch.MaxConnPerHost > bulkCfg.FlushMaxPending {
		maxKeyParallel = cfg.Output.Elasticsearch.MaxConnPerHost - bulkCfg.FlushMaxPending
	}

	return []BulkOpt{
		WithFlushInterval(bulkCfg.FlushInterval),
		WithFlushThresholdCount(bulkCfg.FlushThresholdCount),
		WithFlushThresholdSize(bulkCfg.FlushThresholdSize),
		WithMaxPending(bulkCfg.FlushMaxPending),
		WithAPIKeyMaxParallel(maxKeyParallel),
		WithAPIKeyMaxRequestSize(cfg.Output.Elasticsearch.MaxContentLength),
	}
}
