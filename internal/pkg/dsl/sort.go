// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dsl

type SortOrderT string

const (
	SortAscend  SortOrderT = "asc"
	SortDescend SortOrderT = "desc"
)

func (n *Node) Sort() *Node {
	childNode := n.findOrCreateChildByName(kKeywordSort)
	childNode.nodeList = nodeListT{}
	return childNode
}

func (n *Node) SortOrder(field string, order SortOrderT) {
	if n.nodeList == nil {
		panic("Parent should be sort node")
	}

	if n.leaf != nil {
		panic("Cannot add child to leaf node")
	}

	defaultOrder := SortAscend
	if field == "_score" {
		defaultOrder = SortDescend
	}

	if order == defaultOrder {
		n.nodeList = append(n.nodeList, &Node{leaf: field})
	} else {
		childNode := n.appendOrSetChildNode(field)
		childNode.leaf = order
	}
}

/*
func (q *QueryN) SortOpt(field string, order SortOrder, opts ...SortOpt) {
	// TODO
}
*/
