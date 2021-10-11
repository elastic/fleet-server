// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration
// +build !integration

package policy

import (
	"fmt"
	"math/rand"
	"testing"
)

// Base case, should be empty
func TestSub_Empty(t *testing.T) {

	head := makeHead()

	if !head.isEmpty() {
		t.Error("Expected empty list with only head")
	}
}

// Iteratively pushBack n items up to N.
// Validate order on popFront.
func TestSub_PushBackN(t *testing.T) {

	head := makeHead()

	N := 32

	for n := 1; n <= N; n++ {

		nodes := make([]*subT, 0, n)
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("policy%d", i)
			nn := NewSub(name, "", 0, 0)
			head.pushBack(nn)
			nodes = append(nodes, nn)
		}

		if head.isEmpty() {
			t.Error("head should not be empty after push")
		}

		// Validate all there
		j := 0
		iter := NewIterator(head)
		for sub := iter.Next(); sub != nil; sub = iter.Next() {
			if sub.policyId != nodes[j].policyId {
				t.Error(j, ": misaligned unlink", sub.policyId, nodes[j].policyId)
			}
			j = j + 1
		}

		for i := 0; i < n; i++ {

			sub := head.popFront()
			if sub.policyId != nodes[i].policyId {
				t.Error("misalign on popFront")
			}
		}

		if !head.isEmpty() {
			t.Error("Expect empty list after popFront")
		}

	}
}

// Iteratively pushFront n items up to N.
// Validate order on popFront.
func TestSub_PushFrontN(t *testing.T) {

	head := makeHead()

	N := 32

	for n := 1; n <= N; n++ {

		nodes := make([]*subT, 0, n)
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("policy%d", i)
			nn := NewSub(name, "", 0, 0)
			head.pushFront(nn)
			nodes = append(nodes, nn)
		}

		if head.isEmpty() {
			t.Error("head should not be empty after push")
		}

		// Validate all there
		j := n - 1
		iter := NewIterator(head)
		for sub := iter.Next(); sub != nil; sub = iter.Next() {
			if sub.policyId != nodes[j].policyId {
				t.Error(j, ": misaligned unlink", sub.policyId, nodes[j].policyId)
			}
			j = j - 1
		}

		for i := 0; i < n; i++ {

			sub := head.popFront()
			if sub.policyId != nodes[n-i-1].policyId {
				t.Error("misalign on popFront")
			}
		}

		if !head.isEmpty() {
			t.Error("Expect empty list after popFront")
		}

	}
}

// Push either to front or back randomly.  Validate order.
func TestSub_PushRandom(t *testing.T) {

	head := makeHead()

	N := rand.Intn(4096) + 1

	nodes := make([]*subT, 0, N)
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("policy%d", i)
		nn := NewSub(name, "", 0, 0)

		if rand.Intn(2) == 1 {
			head.pushBack(nn)
			nodes = append(nodes, nn)
		} else {
			head.pushFront(nn)
			nodes = append([]*subT{nn}, nodes...)
		}
	}

	if head.isEmpty() {
		t.Error("head should not be empty after push")
	}

	j := 0
	iter := NewIterator(head)
	for sub := iter.Next(); sub != nil; sub = iter.Next() {
		if sub.policyId != nodes[j].policyId {
			t.Error(j, ": misaligned unlink", sub.policyId, nodes[j].policyId)
		}
		j = j + 1
	}
}

// Generate N nodes.  Unlink randomly.
// Validate order on each unlink.
func TestSub_UnlinkRandomN(t *testing.T) {

	head := makeHead()

	N := rand.Intn(4096) + 1

	nodes := make([]*subT, 0, N)
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("policy%d", i)
		nn := NewSub(name, "", 0, 0)
		head.pushBack(nn)
		nodes = append(nodes, nn)
	}

	if head.isEmpty() {
		t.Error("head should not be empty after push")
	}

	for i := 0; i < N; i++ {
		idx := rand.Intn(len(nodes))
		sub := nodes[idx]
		sub.unlink()
		nodes = append(nodes[:idx], nodes[idx+1:]...)

		j := 0
		iter := NewIterator(head)
		for sub = iter.Next(); sub != nil; sub = iter.Next() {
			if sub.policyId != nodes[j].policyId {
				t.Error(j, ": misaligned unlink", sub.policyId, nodes[j].policyId)
			}
			j = j + 1
		}
	}

	if !head.isEmpty() {
		t.Error("head should be empty")
	}
}

func BenchmarkSubsSimple(b *testing.B) {

	head := makeHead()
	nn := NewSub("", "", 0, 0)
	for i := 0; i < b.N; i++ {
		head.pushBack(nn)
		head.popFront()
	}
}

func BenchmarkSubs(b *testing.B) {
	benchmarks := []int{
		32,
		1024,
		2048,
		65536,
		131072,
		524288,
	}

	max := benchmarks[len(benchmarks)-1]

	head := makeHead()
	subs := make([]*subT, 0, max)

	for i := 0; i < max; i++ {
		name := fmt.Sprintf("policy%d", i)
		nn := NewSub(name, "", 0, 0)
		subs = append(subs, nn)
	}

	for _, bm := range benchmarks {
		b.Run(fmt.Sprintf("%d", bm), func(b *testing.B) {

			for i := 0; i < b.N; i++ {
				for j := 0; j < bm; j++ {
					head.pushBack(subs[j])
				}

				for j := 0; j < bm; j++ {
					subs[j].unlink()
				}
			}

		})
	}
}
