// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dsl

type RangeOpt func(nodeMapT)

func WithRangeGT(v interface{}) RangeOpt {
	return func(nmap nodeMapT) {
		nmap[kKeywordGreaterThan] = &Node{leaf: v}
	}
}

func (n *Node) Range(field string, opts ...RangeOpt) {

	fieldNode := &Node{
		nodeMap: make(nodeMapT),
	}

	for _, o := range opts {
		o(fieldNode.nodeMap)
	}

	childNode := n.appendOrSetChildNode("range")
	childNode.nodeMap = nodeMapT{
		field: fieldNode,
	}
}
