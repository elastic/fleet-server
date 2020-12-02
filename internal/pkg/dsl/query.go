// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dsl

func (n *Node) Query() *Node {
	return n.findOrCreateChildByName(kKeywordQuery)
}

func (n *Node) Bool() *Node {
	return n.findOrCreateChildByName(kKeywordBool)
}

func (n *Node) Must() *Node {
	childNode := n.findOrCreateChildByName(kKeywordMust)
	if childNode.nodeList == nil {
		childNode.nodeList = nodeListT{}
	}
	return childNode
}

func (n *Node) MustNot() *Node {
	childNode := n.findOrCreateChildByName(kKeywordMustNot)
	if childNode.nodeList == nil {
		childNode.nodeList = nodeListT{}
	}
	return childNode
}
