// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package es provides utilities to interact with Elasticsearch.
//
// For the most part the fleet-server uses the go-elasticsearch client directly.
// The es package has structs for encoding/decoding results as well as some utility calls to get version numbers and do some index manipulation.
package es
