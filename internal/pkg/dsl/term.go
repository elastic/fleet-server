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
