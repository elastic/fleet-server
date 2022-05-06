// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package dsl implements an incomplete elasticsearch DSL query builder.
// WARNING: Grossly incomplete and probably broken.
package dsl

import (
	"encoding/json"
)

type nodeMapT map[string]*Node
type nodeListT []*Node

type Node struct {
	leaf        interface{}
	nodeMap     nodeMapT
	nodeList    nodeListT
	preventNull bool
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
	if n.preventNull {
		return []byte("{}"), nil
	}
	return []byte(kKeywordNULL), nil
}

func (n *Node) MustMarshalJSON() []byte {
	res, err := n.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return res
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
func (n *Node) appendOrSetChildNode(keyword string) *Node {
	childNode := &Node{}

	switch {
	case n.leaf != nil:
		panic("Cannot add child to leaf node")
	case n.nodeList != nil:
		parentNode := Node{
			nodeMap: nodeMapT{keyword: childNode},
		}
		n.nodeList = append(n.nodeList, &parentNode)
	default:
		if n.nodeMap == nil {
			n.nodeMap = nodeMapT{keyword: childNode}
		} else {
			n.nodeMap[keyword] = childNode
		}
	}

	return childNode
}
