// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package bulk

import (
	"github.com/elastic/fleet-server/v7/internal/pkg/danger"

	"go.elastic.co/apm/v2"
)

type Buf = danger.Buf

// bulkT is generally allocated in the bulk engines's 'blkPool'
// However, the multiOp API's will allocate directly in large blocks.

type bulkT struct {
<<<<<<< HEAD
	action   actionT    // requested actions
	flags    flagsT     // execution flags
	idx      int32      // idx of originating request, used in mulitOp
	ch       chan respT // response channel, caller is waiting synchronously
	buf      Buf        // json payload to be sent to elastic
	next     *bulkT     // pointer to next bulkT, used for fast internal queueing
	spanLink *apm.SpanLink
=======
	action       actionT    // requested actions
	flags        flagsT     // execution flags
	idx          int32      // idx of originating request, used in mulitOp
	ch           chan respT // response channel, caller is waiting synchronously
	buf          Buf        // json payload to be sent to elastic
	next         *bulkT     // pointer to next bulkT, used for fast internal queueing
	spanLink     apm.SpanLink
	hasSpanLink  bool
	dedupeKey    string // enrollment dedup key (enrollment_id); routes to kQueueEnrollSearch when set
	refreshIndex string // index to refresh before msearch in kQueueEnrollSearch
>>>>>>> 3890bbb (feat: batch enrollment FindAgent searches with pre-refresh dedup (#7662))
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
	ActionUpdateAPIKey
	ActionRead
	ActionSearch
	ActionFleetSearch
)

var actionStrings = []string{
	"create",
	"delete",
	"index",
	"update",
	"update_api_key",
	"read",
	"search",
	"fleet_search",
}

func (a actionT) String() string {
	return actionStrings[a]
}

func (blk *bulkT) reset() {
	blk.action = 0
	blk.flags = 0
	blk.idx = 0
	blk.buf.Reset()
	blk.next = nil
<<<<<<< HEAD
	blk.spanLink = nil
=======
	blk.spanLink = apm.SpanLink{}
	blk.hasSpanLink = false
	blk.dedupeKey = ""
	blk.refreshIndex = ""
>>>>>>> 3890bbb (feat: batch enrollment FindAgent searches with pre-refresh dedup (#7662))
}

type respT struct {
	err  error
	idx  int32
	data interface{}
}
