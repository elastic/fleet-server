// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

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
