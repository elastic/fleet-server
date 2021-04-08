// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"github.com/elastic/fleet-server/v7/internal/pkg/danger"
)

type Buf = danger.Buf

// bulkT is generally allocated in the bulk engines's 'blkPool'
// However, the multiOp API's will allocate directly in large blocks.

type bulkT struct {
	action actionT    // requested actions
	flags  flagsT     // execution flags
	idx    int32      // idx of originating requeset, used in mulitOp
	ch     chan respT // response channel, caller is waiting synchronously
	buf    Buf        // json payload to be sent to elastic
	next   *bulkT     // pointer to next bulkT, used for fast internal queueing
}

type flagsT int8

const (
	flagRefresh flagsT = 1 << iota
)

func (ft flagsT) Has(f flagsT) bool {
	return ft&f != 0
}

func (ft *flagsT) Set(f flagsT) {
	*ft = *ft | f
}

type actionT int8

const (
	ActionCreate actionT = iota
	ActionDelete
	ActionIndex
	ActionUpdate
	ActionRead
	ActionSearch
)

var actionStrings = []string{
	"create",
	"delete",
	"index",
	"update",
	"read",
	"search",
}

func (a actionT) Str() string {
	return actionStrings[a]
}

func (blk *bulkT) reset() {
	blk.action = 0
	blk.flags = 0
	blk.idx = 0
	blk.buf.Reset()
	blk.next = nil
}

func newBlk() interface{} {
	return &bulkT{
		ch: make(chan respT, 1),
	}
}

type respT struct {
	err  error
	idx  int32
	data interface{}
}
