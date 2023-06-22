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
)

const (
	// integration name is substituted in
	FileHeaderIndexPattern = ".fleet-filedelivery-meta-%s"
	FileDataIndexPattern   = ".fleet-filedelivery-data-%s"

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
	q, err := MetaByIDAndAgent.Render(map[string]interface{}{
		FieldDocID:      fileID,
		"target_agents": agentID,
	})
	if err != nil {
		return nil, err
	}

	result, err := bulker.Search(ctx, fmt.Sprintf(FileHeaderIndexPattern, "*"), q)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func readChunkStream(client *elasticsearch.Client, idx string, docID string) (io.ReadCloser, error) {

	res, err := client.Get(idx, docID, func(req *esapi.GetRequest) {
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
