// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import "github.com/elastic/fleet-server/v7/internal/pkg/dsl"

func prepareFindByField(field string, params map[string]any) *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()

	for k, v := range params {
		root.Param(k, v)
	}

	root.Query().Bool().Filter().Term(field, tmpl.Bind(field), nil)

	tmpl.MustResolve(root)
	return tmpl
}
