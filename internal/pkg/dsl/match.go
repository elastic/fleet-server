// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dsl

func (n *Node) MatchAll() *Node {
	c := n.findOrCreateChildByName(kKeywordMatchAll)
	c.preventNull = true
	return c
}

func (n *Node) MatchNone() *Node {
	c := n.findOrCreateChildByName(kKeywordMatchNone)
	c.preventNull = true
	return c
}
