// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dsl

func (n *Node) Term(field string, value interface{}, boost *float64) {
	childNode := n.appendOrSetChildNode(kKeywordTerm)

	leaf := value

	if boost != nil {
		leaf = &struct {
			Value interface{} `json:"value"`
			Boost *float64    `json:"boost,omitempty"`
		}{
			value,
			boost,
		}
	}

	childNode.nodeMap = nodeMapT{field: &Node{
		leaf: leaf,
	}}
}

func (n *Node) Terms(field string, value interface{}, boost *float64) {
	childNode := n.appendOrSetChildNode(kKeywordTerms)

	childNode.nodeMap = nodeMapT{
		field: &Node{leaf: value},
	}

	if boost != nil {
		childNode.nodeMap[kKeywordBoost] = &Node{leaf: *boost}
	}
}
