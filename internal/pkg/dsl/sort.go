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

type SortOrderT string

const (
	SortAscend  SortOrderT = "asc"
	SortDescend            = "desc"
)

func (n *Node) Sort() *Node {
	childNode := n.findOrCreateChildByName(kKeywordSort)
	childNode.nodeList = nodeListT{}
	return childNode
}

func (n *Node) SortOrder(field string, order SortOrderT) {
	if n.nodeList == nil {
		panic("Parent should be sort node")
	}

	if n.leaf != nil {
		panic("Cannot add child to leaf node")
	}

	defaultOrder := SortAscend
	if field == "_score" {
		defaultOrder = SortDescend
	}

	if order == defaultOrder {
		n.nodeList = append(n.nodeList, &Node{leaf: field})
	} else {
		childNode := n.appendOrSetChildNode(field)
		childNode.leaf = order
	}
}

/*
func (q *QueryN) SortOpt(field string, order SortOrder, opts ...SortOpt) {
	// TODO
}
*/
