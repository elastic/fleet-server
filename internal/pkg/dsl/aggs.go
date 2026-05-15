// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dsl

func (n *Node) Aggs() *Node {
	return n.findOrCreateChildByName(kKeywordAggs)
}

func (n *Node) Agg(name string) *Node {
	return n.findOrCreateChildByName(name)
}

func (n *Node) Max() *Node {
	return n.findOrCreateChildByName(kKeywordMax)
}
