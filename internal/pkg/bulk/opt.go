// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"github.com/rs/zerolog"
	"strconv"
	"time"
)

//-----
// Transaction options

type optionsT struct {
	Refresh         bool
	RetryOnConflict string
	Indices         []string
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

// Applicable to search
func WithIndex(idx string) Opt {
	return func(opt *optionsT) {
		opt.Indices = append(opt.Indices, idx)
	}
}

//-----
// Bulk API options

type bulkOptT struct {
	flushInterval     time.Duration
	flushThresholdCnt int
	flushThresholdSz  int
	maxPending        int
}

type BulkOpt func(*bulkOptT)

// Interval on which any pending transactions will be flushed to bulker
func WithFlushInterval(d time.Duration) BulkOpt {
	return func(opt *bulkOptT) {
		opt.flushInterval = d
	}
}

// Cnt of pending transactions that will force flush before interval
func WithFlushThresholdCount(cnt int) BulkOpt {
	return func(opt *bulkOptT) {
		opt.flushThresholdCnt = cnt
	}
}

// Cummulative size in bytes of pending transactions that will force flush before interval
func WithFlushThresholdSize(sz int) BulkOpt {
	return func(opt *bulkOptT) {
		opt.flushThresholdSz = sz
	}
}

// Max number of elastic transactions pending response
func WithMaxPending(max int) BulkOpt {
	return func(opt *bulkOptT) {
		opt.maxPending = max
	}
}

func (o *bulkOptT) MarshalZerologObject(e *zerolog.Event) {
	e.Dur("flushInterval", o.flushInterval)
	e.Int("flushThresholdCnt", o.flushThresholdCnt)
	e.Int("flushThresholdSz", o.flushThresholdSz)
	e.Int("maxPending", o.maxPending)
}
