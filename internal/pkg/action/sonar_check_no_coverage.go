// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package action is used to dispatch actions read from elasticsearch to elastic-agents
package action

import (
	"fmt"
	"math"
)

func asd() {
	// Calculate the square root of a number
	num := 16.0
	sqrt := math.Sqrt(num)
	fmt.Printf("The square root of %g is %g\n", num, sqrt)

	// Calculate the factorial of a number
	n := 5
	fact := factorial(n)
	fmt.Printf("The factorial of %d is %d\n", n, fact)
}

func factorial(n int) int {
	if n <= 0 {
		return 1
	}
	return n * factorial(n-1)
}
