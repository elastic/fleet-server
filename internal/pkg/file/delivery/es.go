// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package delivery

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"go.elastic.co/apm/v2"
)

const (
	// Agent-targeted ephemeral files. Integration name is substituted in
	FileHeaderIndexPattern = ".fleet-fileds-tohost-meta-%s"
	FileDataIndexPattern   = ".fleet-fileds-tohost-data-%s"

	// Long-lived library files, owned by integrations. Integration & target library substituted in
	LibraryFileHeaderIndexPattern = ".%s-fleetfiles-%s-meta"
	LibraryFileDataIndexPattern   = ".%s-fleetfiles-%s-data"

	FieldDocID        = "_id"
	FieldTargetAgents = "file.Meta.target_agents"
	FieldStatus       = "file.Status"
)

var (
	MetaByIDAndAgent = prepareQueryMetaByIDAndAgent()
)

func prepareQueryMetaByIDAndAgent() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	node := root.Query().Bool().Must()
	node.Term(FieldDocID, tmpl.Bind(FieldDocID), nil)
	node.Term(FieldTargetAgents, tmpl.Bind("target_agents"), nil)
	node.Term(FieldStatus, file.StatusDone, nil)
	tmpl.MustResolve(root)
	return tmpl
}

func findFileForAgent(ctx context.Context, bulker bulk.Bulk, fileID string, agentID string) (*es.ResultT, error) {
	q, err := MetaByIDAndAgent.Render(map[string]any{
		FieldDocID:      fileID,
		"target_agents": agentID,
	})
	if err != nil {
		return nil, err
	}

	span, ctx := apm.StartSpan(ctx, "searchFile", "search")
	defer span.End()
	result, err := bulker.Search(ctx, fmt.Sprintf(FileHeaderIndexPattern, "*"), q)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func findFileInLibrary(ctx context.Context, bulker bulk.Bulk, fileID string, index string) ([]byte, error) {
	span, ctx := apm.StartSpan(ctx, "searchFile", "search")
	defer span.End()
	result, err := bulker.Read(ctx, index, fileID)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func readChunkStream(ctx context.Context, client *elasticsearch.Client, idx string, docID string) (io.ReadCloser, error) {
	span, ctx := apm.StartSpan(ctx, "getChunk", "get")
	span.Context.SetLabel("index", idx)
	span.Context.SetLabel("chunk", docID)
	defer span.End()
	res, err := client.Get(idx, docID, client.Get.WithContext(ctx), func(req *esapi.GetRequest) {
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set("Accept", "application/cbor")
		req.StoredFields = []string{"data"}
		req.Source = []string{"false"}
	})
	if err != nil {
		return nil, err
	}

	return res.Body, nil
}
