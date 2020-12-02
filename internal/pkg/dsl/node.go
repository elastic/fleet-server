// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dsl

import (
	"encoding/json"
)

// Very basic elastic DSL query builder; grossly incomplete; probably broken.

type nodeMapT map[string]*Node
type nodeListT []*Node

type Node struct {
	leaf     interface{}
	nodeMap  nodeMapT
	nodeList nodeListT
}

func (n *Node) MarshalJSON() ([]byte, error) {

	switch {
	case n.leaf != nil:
		return json.Marshal(n.leaf)
	case n.nodeMap != nil:
		return json.Marshal(n.nodeMap)
	case n.nodeList != nil:
		return json.Marshal(n.nodeList)
	}

	return []byte(kKeywordNULL), nil
}

func (n *Node) findOrCreateChildByName(keyword string) *Node {
	if node, ok := n.nodeMap[keyword]; ok {
		return node
	}

	if n.leaf != nil {
		panic("Cannot add child to leaf node")
	}

	childNode := &Node{}
	if n.nodeMap == nil {
		n.nodeMap = nodeMapT{keyword: childNode}
	} else {
		n.nodeMap[keyword] = childNode
	}

	return childNode
}

// Create child node and add to nodeList if exists, or add fallback to nodeMap.
func (q *Node) appendOrSetChildNode(keyword string) *Node {
	childNode := &Node{}

	switch {
	case q.leaf != nil:
		panic("Cannot add child to leaf node")
	case q.nodeList != nil:
		parentNode := Node{
			nodeMap: nodeMapT{keyword: childNode},
		}
		q.nodeList = append(q.nodeList, &parentNode)
	default:
		if q.nodeMap == nil {
			q.nodeMap = nodeMapT{keyword: childNode}
		} else {
			q.nodeMap[keyword] = childNode
		}
	}

	return childNode
}
