// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

type queueT struct {
	ty      queueType
	cnt     int
	head    *bulkT
	pending int
}

type queueType int

const (
	kQueueBulk queueType = iota
	kQueueRead
	kQueueSearch
	kQueueRefreshBulk
	kQueueRefreshRead
	kNumQueues
)

func (q queueT) Type() string {
	switch q.ty {
	case kQueueBulk:
		return "bulk"
	case kQueueRead:
		return "read"
	case kQueueSearch:
		return "search"
	case kQueueRefreshBulk:
		return "refreshBulk"
	case kQueueRefreshRead:
		return "refreshRead"
	}
	panic("unknown")
}
