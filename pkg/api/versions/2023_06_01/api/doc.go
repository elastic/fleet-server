// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:generate oapi-codegen -generate types -package api -o types.gen.go  openapi.yml
//go:generate oapi-codegen -generate client -package api -o client.gen.go  openapi.yml

// Package api contains the 2023-06-01 client of the fleet-server API.
// Client code is generated from ./openapi.yml
package api
