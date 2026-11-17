// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"os"
)

// printf writes formatted workflow progress to stdout without using fmt.Print*
// (forbidden by forbidigo in the root module).
func printf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stdout, format, args...)
}

// println writes workflow progress lines to stdout without using fmt.Print*.
func println(args ...any) {
	_, _ = fmt.Fprintln(os.Stdout, args...)
}
