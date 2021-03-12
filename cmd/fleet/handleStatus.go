// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
)

func (rt Router) handleStatus(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	status := rt.sm.Status()
	resp := StatusResponse{
		Name: "fleet-server",
		Version: rt.ver,
		Status: status.String(),
	}

	data, err := json.Marshal(&resp)
	if err != nil {
		code := http.StatusInternalServerError
		log.Error().Err(err).Int("code", code).Msg("fail status")
		http.Error(w, err.Error(), code)
		return
	}

	code := http.StatusServiceUnavailable
	if status == proto.StateObserved_DEGRADED || status == proto.StateObserved_HEALTHY {
		code = http.StatusOK
	}
	w.WriteHeader(code)
	if _, err = w.Write(data); err != nil {
		if err != context.Canceled {
			log.Error().Err(err).Int("code", code).Msg("fail status")
		}
	}
}
