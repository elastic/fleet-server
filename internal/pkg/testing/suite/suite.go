// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

// Package suite wraps a testify/suite.Suite
package suite

import (
	tsuite "github.com/stretchr/testify/suite"
)

type RunningSuite struct {
	tsuite.Suite
}

func (s *RunningSuite) SetupSuite() {
}

func (s *RunningSuite) TearDownSuite() {
}
