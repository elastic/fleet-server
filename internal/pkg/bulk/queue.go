// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
	kQueueFleetSearch
	kQueueRefreshBulk
	kQueueRefreshRead
	kQueueAPIKeyUpdate
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
	case kQueueFleetSearch:
		return "fleetSearch"
	case kQueueRefreshBulk:
		return "refreshBulk"
	case kQueueRefreshRead:
		return "refreshRead"
	case kQueueAPIKeyUpdate:
		return "apiKeyUpdate"
	}
	panic("unknown")
}
