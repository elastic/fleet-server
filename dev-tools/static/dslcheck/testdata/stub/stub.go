// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package stub provides a minimal Tmpl type for dslcheck analyzer tests.
package stub

// Tmpl is a stand-in for dsl.Tmpl. The analyzer checks the type name "Tmpl"
// not the import path, so this stub triggers the same analysis.
type Tmpl struct{}

func NewTmpl() *Tmpl        { return &Tmpl{} }
func (t *Tmpl) Bind(string) {}
