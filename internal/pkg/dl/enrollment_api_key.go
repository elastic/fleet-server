// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import "fleet/internal/pkg/dsl"

// PrepareQueryAllAPIKeys prepares a query. For migration only.
func PrepareQueryAllAPIKeys(size uint64) ([]byte, error) {
	tmpl := dsl.NewTmpl()

	root := dsl.NewRoot()
	root.Size(size)

	err := tmpl.Resolve(root)
	if err != nil {
		return nil, err
	}
	return tmpl.Render(nil)
}
