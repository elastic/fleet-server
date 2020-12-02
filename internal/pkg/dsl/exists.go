// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dsl

func (n *Node) Exists(field string) {
	childNode := n.findOrCreateChildByName(kKeywordExists)
	childNode.nodeMap = nodeMapT{kKeywordField: &Node{
		leaf: field,
	}}
}
