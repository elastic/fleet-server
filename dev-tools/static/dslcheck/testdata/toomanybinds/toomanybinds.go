// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package toomanybinds contains cases that must trigger dslcheck.
package toomanybinds

import "example.com/dslcheck-testdata/stub"

func NineBinds() {
	tmpl := stub.NewTmpl()
	tmpl.Bind("a")
	tmpl.Bind("b")
	tmpl.Bind("c")
	tmpl.Bind("d")
	tmpl.Bind("e")
	tmpl.Bind("f")
	tmpl.Bind("g")
	tmpl.Bind("h")
	tmpl.Bind("i") // want `tmpl has 9 Bind\(\) calls in this function; renderPairsCap is 8`
}
