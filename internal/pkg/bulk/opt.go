// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package bulk

import (
	"time"
)

//-----
// Transaction options

type optionsT struct {
	Refresh bool
}

type Opt func(*optionsT)

func WithRefresh() Opt {
	return func(opt *optionsT) {
		opt.Refresh = true
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

// Cummulative size of pending transactions that will force flush before interval
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
