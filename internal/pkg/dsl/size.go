// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dsl

func (n *Node) Size(sz uint64) {
	childNode := n.findOrCreateChildByName(kKeywordSize)
	childNode.leaf = sz
}

// WithSize allows to parameterize the size
func (n *Node) WithSize(v interface{}) {
	n.nodeMap[kKeywordSize] = &Node{leaf: v}
}
