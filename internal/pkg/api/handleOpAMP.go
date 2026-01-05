// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"fmt"
	"io"
	"net/http"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/gofrs/uuid/v5"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"
)

const (
	kOpAMPMod = "opAMP"
)

type OpAMPT struct {
	bulk  bulk.Bulk
	cache cache.Cache
}

func NewOpAMPT(bulker bulk.Bulk, cache cache.Cache) *OpAMPT {
	oa := &OpAMPT{
		bulk:  bulker,
		cache: cache,
	}
	return oa
}

func (oa OpAMPT) handleOpAMP(zlog zerolog.Logger, r *http.Request, w http.ResponseWriter) error {
	if _, err := authAPIKey(r, oa.bulk, oa.cache); err != nil {
		zlog.Debug().Err(err).Msg("unauthenticated opamp request")
		return err
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return &BadRequestErr{msg: "failed to read AgentToServer request body"}
	}
	defer r.Body.Close()

	var aToS protobufs.AgentToServer
	if err := proto.Unmarshal(body, &aToS); err != nil {
		return &BadRequestErr{msg: "failed to unmarshal AgentToServer message"}
	}

	instanceUID, err := uuid.FromBytes(aToS.InstanceUid)
	if err != nil {
		return &BadRequestErr{msg: "failed to parse instance_uid from AgentToServer message"}
	}
	zlog.Debug().
		Str("instance_uid", instanceUID.String()).
		Msg("received AgentToServer message from agent")

	sToA := protobufs.ServerToAgent{}
	resp, err := proto.Marshal(&sToA)
	if err != nil {
		return fmt.Errorf("failed to marshal ServerToAgent response body: %w", err)
	}

	w.Write(resp)

	return nil
}
