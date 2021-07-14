// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

type subT struct {
	policyId string
	agentId  string // not logically necessary; cached for logging
	revIdx   int64
	coordIdx int64

	next *subT
	prev *subT

	ch chan *ParsedPolicy
}

func NewSub(policyId, agentId string, revIdx, coordIdx int64) *subT {
	return &subT{
		policyId: policyId,
		agentId:  agentId,
		revIdx:   revIdx,
		coordIdx: coordIdx,
		ch:       make(chan *ParsedPolicy, 1),
	}
}

func makeHead() *subT {
	sub := &subT{}
	sub.next = sub
	sub.prev = sub
	return sub
}

func (n *subT) pushFront(nn *subT) {
	nn.next = n.next
	nn.prev = n
	n.next.prev = nn
	n.next = nn
}

func (n *subT) pushBack(nn *subT) {
	nn.next = n
	nn.prev = n.prev
	n.prev.next = nn
	n.prev = nn
}

func (n *subT) popFront() *subT {
	if n.next == n {
		return nil
	}
	s := n.next
	s.unlink()
	return s
}

func (n *subT) unlink() bool {
	if n.next == nil || n.prev == nil {
		return false
	}

	n.prev.next = n.next
	n.next.prev = n.prev
	n.next = nil
	n.prev = nil
	return true
}

func (n *subT) isEmpty() bool {
	return n.next == n
}

func (s *subT) isUpdate(policy *model.Policy) bool {

	pRevIdx := policy.RevisionIdx
	pCoordIdx := policy.CoordinatorIdx

	return (pRevIdx > s.revIdx && pCoordIdx > 0) || (pRevIdx == s.revIdx && pCoordIdx > s.coordIdx)
}

// Output returns a new policy that needs to be sent based on the current subscription.
func (sub *subT) Output() <-chan *ParsedPolicy {
	return sub.ch
}

type subIterT struct {
	head *subT
	cur  *subT
}

func NewIterator(head *subT) *subIterT {
	return &subIterT{
		head: head,
		cur:  head,
	}
}

func (it *subIterT) Next() *subT {
	next := it.cur.next
	if next == it.head {
		return nil
	}
	it.cur = next
	return next
}

func (it *subIterT) Unlink() {
	prev := it.cur.prev
	it.cur.unlink()
	it.cur = prev
}
