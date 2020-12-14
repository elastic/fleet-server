// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dsl"
)

const (
	maxSeqNo = "max_seq_no"
)

var (
	QuerySeqNoByDocID = prepareFindSeqNoByDocID()
)

func prepareFindSeqNoByDocID() *dsl.Tmpl {
	root := dsl.NewRoot()
	root.Param(seqNoPrimaryTerm, true)
	root.Param(FieldSource, []string{FieldSeqNo})

	tmpl := dsl.NewTmpl()

	root.Query().Bool().Filter().Term(FieldId, tmpl.Bind(FieldId), nil)
	tmpl.MustResolve(root)
	return tmpl
}

func FindSeqNoByDocID(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, index, docId string) (seqno int64, err error) {
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
