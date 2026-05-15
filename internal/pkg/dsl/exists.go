// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dsl

func (n *Node) Exists(field string) {
	childNode := n.findOrCreateChildByName(kKeywordExists)
	childNode.nodeMap = nodeMapT{kKeywordField: &Node{
		leaf: field,
	}}
}
