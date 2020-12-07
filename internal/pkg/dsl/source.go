// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dsl

func (n *Node) Source() *Node {
	return n.findOrCreateChildByName(kKeywordSource)
}

func (n *Node) Excludes(arr ...string) *Node {
	childNode := n.appendOrSetChildNode(kKeywordExcludes)
	childNode.leaf = arr
	return childNode
}

func (n *Node) Includes(arr ...string) *Node {
	childNode := n.appendOrSetChildNode(kKeywordIncludes)
	childNode.leaf = arr
	return childNode
}
