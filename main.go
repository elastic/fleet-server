// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:generate go tool -modfile ./dev-tools/go.mod github.com/elastic/go-json-schema-generate/cmd/schema-generate -esdoc -s -cm "{\"Api\": \"API\", \"Id\": \"ID\"}" -o internal/pkg/model/schema.go -p model model/schema.json
//go:generate go tool -modfile ./dev-tools/go.mod github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config model/oapi-cfg.yml model/openapi.yml
//go:generate go tool -modfile ./dev-tools/go.mod github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen -generate types -package api -o pkg/api/types.gen.go  model/openapi.yml
//go:generate go tool -modfile ./dev-tools/go.mod github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen -generate client -package api -o pkg/api/client.gen.go  model/openapi.yml
//go:generate go fmt internal/pkg/model/schema.go
//go:generate go fmt internal/pkg/api/openapi.gen.go
//go:generate go fmt pkg/api/types.gen.go
//go:generate go fmt pkg/api/client.gen.go

package main

import (
	"fmt"
	"os"

	"github.com/elastic/fleet-server/v7/cmd/fleet"
	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/version"
)

var (
	Version   string = version.DefaultVersion
	Commit    string
	BuildTime string
)

func main() {
	cmd := fleet.NewCommand(build.Info{
		Version:   Version,
		Commit:    Commit,
		BuildTime: build.Time(BuildTime),
	})
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
