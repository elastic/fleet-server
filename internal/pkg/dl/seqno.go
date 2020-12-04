// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"errors"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dsl"
)

const (
	maxSeqNo = "max_seq_no"
)

var ErrNotFound = errors.New("not found")

func PrepareQuerySeqNoByDocId() (*dsl.Tmpl, error) {
	root := dsl.NewRoot()
	root.Param(seqNoPrimaryTerm, true)
	root.Param(FieldSource, []string{FieldSeqNo})

	tmpl := dsl.NewTmpl()

	root.Query().Bool().Filter().Term(FieldId, tmpl.Bind(FieldId), nil)
	err := tmpl.Resolve(root)
	if err != nil {
		return nil, err
	}
	return tmpl, err
}

func QuerySeqNoByDocId(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, index, docId string) (seqno int64, err error) {
	seqno = defaultSeqNo

	res, err := SearchWithOneParam(ctx, bulker, tmpl, index, FieldId, docId)
	if err != nil {
		return seqno, err
	}

	if len(res.Hits) == 0 {
		return seqno, ErrNotFound
	}
	return res.Hits[0].SeqNo, nil
}
