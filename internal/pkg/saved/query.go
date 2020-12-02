// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package saved

import (
	"fmt"

	"fleet/internal/pkg/dsl"
)

func NewQuery(ty string) *dsl.Node {

	root := dsl.NewRoot()

	// Require the type
	root.Query().Bool().Must().Term("type", ty, nil)

	return root
}

func ScopeField(ty, field string) string {
	return fmt.Sprintf("%s.%s", ty, field)
}

type ScopeFuncT func(field string) string

func ScopeFunc(ty string) ScopeFuncT {
	prefix := fmt.Sprintf("%s.", ty)
	return func(field string) string {
		return prefix + field
	}
}

/*

1) saved.SearchNode(ctx, dsl.Node)
2) saved.SearchRaw(ctx, []byte)
3) fix policy to support N looksup in parallel
4) multisearch? how return hits?
5) strip out comments...
6) templatize call to get agent id at beginning of program



	q.Field(scopedField, value, boost)

type treeMap map[string]*QueryN
type QueryN struct {
	leaf interface{}
	tree treeMap
	array []*QueryN
}


func (q *QueryN) MarshalJSON() ([]byte, error) {

	switch {
	case q.leaf != nil:
		return json.Marshal(q.leaf)
	case q.tree != nil:
		return json.Marshal(q.tree)
	case q.array != nil:
		return json.Marshal(q.array)
	}

	return []byte("null"), nil
}

func (q *QueryN) Query() *QueryN {
	if node, ok := q.tree["query"]; ok {
		return node
	}

	if q.tree == nil {
		q.tree = make(map[string]*QueryN)
	}

	node := &QueryN{}
	q.tree["query"] = node
	return node
}

func (q *QueryN) Bool() *QueryN {
	if node, ok := q.tree["bool"]; ok {
		return node
	}

	if q.tree == nil {
		q.tree = make(map[string]*QueryN)
	}

	node := &QueryN{}
	q.tree["bool"] = node
	return node
}

func (q *QueryN) Must() *QueryN {
	if node, ok := q.tree["must"]; ok {
		return node
	}

	if q.tree == nil {
		q.tree = make(map[string]*QueryN)
	}

	node := &QueryN{
		array: make([]*QueryN, 0),
	}
	q.tree["must"] = node
	return node
}

func (q *QueryN) Term() *QueryN {
	return q.makeChildNode("term")
}

func (q *QueryN) makeChildNode(key string) *QueryN {
	node := &QueryN{}
	if q.array != nil {
		tNode := QueryN{
			tree: map[string]*QueryN{key:node},
		}
		q.array = append(q.array, &tNode)

	} else {
		if q.tree == nil {
			q.tree = make(map[string]*QueryN)
		}
		q.tree[key] = node
	}

	return node
}

func (q *QueryN) Field(field string, value interface{}, boost *float64) {
	if q.tree == nil {
		q.tree = make(map[string]*QueryN)
	}

	var leaf interface{}

	switch boost {
	case nil:
		leaf = value
	default:
		leaf = &struct {
			Value interface{} `json:"value"`
			Boost *float64 `json:"boost,omitempty"`
		} {
			value,
			boost,
		}
	}

	node := &QueryN{
		leaf: leaf,
	}

	q.tree[field] = node
}

func (q *QueryN) SavedField(ty, field string, value interface{}, boost *float64) {
	scopedField := fmt.Sprintf("%s.%s", ty, field)
	q.Field(scopedField, value, boost)
}

type RangeOpt func(treeMap)

func WithRangeGT(v interface{}) RangeOpt {
	return func(tmap treeMap) {
		tmap["gt"] = &QueryN{leaf:v}
	}
}

func (q *QueryN) Range(field string, opts ...RangeOpt) {

	fieldNode := &QueryN{
		tree: make(treeMap),
	}

	for _, o := range opts {
		o(fieldNode.tree)
	}

	node := q.makeChildNode("range")
	node.tree = map[string]*QueryN{
		field: fieldNode,
	}
}

func (q *QueryN) Size(sz uint64) {
	if q.tree == nil {
		q.tree = make(treeMap)
	}
	q.tree["size"] = &QueryN {
		leaf: sz,
	}
}

func (q *QueryN) Sort() *QueryN {
	n := q.makeChildNode("sort")
	n.array = make([]*QueryN, 0)
	return n
}

type SortOrderT string

const (
	SortAscend SortOrderT = "asc"
	SortDescend = "desc"
)

func (q *QueryN) SortOrder(field string, order SortOrderT) {
	if q.array == nil {
		panic("Parent should be sort node")
	}

	defaultOrder := SortAscend
	if field == "_score" {
		defaultOrder = SortDescend
	}

	if order == defaultOrder {
		q.array = append(q.array, &QueryN{leaf:field})
	} else {
		n := q.makeChildNode(field)
		n.leaf = order
	}
}


func (q *QueryN) SortOpt(field string, order SortOrder, opts ...SortOpt) {
	// TODO
}
*/
