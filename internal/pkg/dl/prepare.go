// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import "fleet/internal/pkg/dsl"

func prepareFindByField(field string, params map[string]interface{}) *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()

	for k, v := range params {
		root.Param(k, v)
	}

	root.Query().Bool().Filter().Term(field, tmpl.Bind(field), nil)

	tmpl.MustResolve(root)
	return tmpl
}
