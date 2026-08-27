// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build ignore

// fixschema converts optional time.Time fields in model.Agent to *time.Time.
// Go's encoding/json omitempty is ineffective for struct types: a zero time.Time
// serializes as "0001-01-01T00:00:00Z" instead of being omitted, causing issues
// such as Kibana treating enrolled agents as unenrolled (non-null unenrolled_at).
// The schema-generate tool does not support pointer types, so this post-processing
// step is applied after generation.
package main

import (
	"os"
	"strings"
)

// agentOptionalTimeFields are the time.Time fields in model.Agent that must be
// *time.Time so that omitempty correctly omits them when unset.
var agentOptionalTimeFields = []string{
	"AuditUnenrolledTime",
	"LastCheckin",
	"LastUpdated",
	"UnenrolledAt",
	"UnenrollmentStartedAt",
	"UpdatedAt",
	"UpgradeStartedAt",
	"UpgradedAt",
}

const schemaFile = "internal/pkg/model/schema.go"

func main() {
	filename := schemaFile
	if len(os.Args) >= 2 && os.Args[1] != "" {
		filename = os.Args[1]
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	content := string(data)
	for _, field := range agentOptionalTimeFields {
		// Replace "FieldName time.Time " with "FieldName *time.Time "
		// Only match value-type declarations (not already-pointer ones).
		old := "\t" + field + " time.Time "
		new := "\t" + field + " *time.Time "
		content = strings.ReplaceAll(content, old, new)
	}
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		panic(err)
	}
}
