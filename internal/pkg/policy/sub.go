// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

type subT struct {
	policyID string
	agentID  string // not logically necessary; cached for logging
	revIdx   int64

	next *subT
	prev *subT

	ch chan *ParsedPolicy
}

func NewSub(policyID, agentID string, revIdx int64) *subT {
	return &subT{
		policyID: policyID,
		agentID:  agentID,
		revIdx:   revIdx,
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

func (n *subT) unlink() bool { //nolint:unparam // useful to return this if we ever test
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

func (n *subT) isUpdate(policy *model.Policy) bool {
	pRevIdx := policy.RevisionIdx

	return pRevIdx != n.revIdx
}

// Output returns a new policy that needs to be sent based on the current subscription.
func (n *subT) Output() <-chan *ParsedPolicy {
	return n.ch
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
