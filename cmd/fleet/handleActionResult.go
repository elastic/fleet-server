// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dl"
	"fleet/internal/pkg/model"

	"github.com/go-playground/validator/v10"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
)

func (rt *Router) handleActionResult(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")

	err := _handleActionResult(w, r, id, rt.ct.bulker, rt.validate)

	if err != nil {
		code := http.StatusBadRequest
		// Don't log connection drops
		if err != context.Canceled {
			log.Error().Err(err).Int("code", code).Msg("Fail Action Result")
		}

		http.Error(w, err.Error(), code)
	}
}

func _handleActionResult(w http.ResponseWriter, r *http.Request, id string, bulker bulk.Bulk, validate *validator.Validate) error {
	agent, err := authAgent(r, id, bulker)
	if err != nil {
		return err
	}

	raw, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	var req ActionResultRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return err
	}

	if err := validate.Struct(req); err != nil {
		return err
	}

	log.Trace().RawJSON("raw", raw).Msg("Action result request")

	acr := model.ActionResult{
		ActionId: req.ActionId,
		AgentId:  agent.Id,
		Data:     req.Data,
		Error:    req.Error,
	}
	if _, err := dl.CreateActionResult(r.Context(), bulker, acr); err != nil {
		return err
	}

	resp := ActionResultResponse{true}

	data, err := json.Marshal(&resp)
	if err != nil {
		return err
	}

	if _, err = w.Write(data); err != nil {
		return err
	}

	return nil
}
