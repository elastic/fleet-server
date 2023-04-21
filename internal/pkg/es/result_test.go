// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package es

import (
	"encoding/json"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/xid"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

func TestHitUnmarshal(t *testing.T) {
	action := model.Action{
		ESDocument: model.ESDocument{
			Id:      xid.New().String(),
			SeqNo:   2,
			Version: 1,
		},
		ActionID: uuid.Must(uuid.NewV4()).String(),
	}

	body, err := json.Marshal(action)
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshall action iwth json and check that ES properties are not set
	var a model.Action
	err = json.Unmarshal(body, &a)
	if err != nil {
		t.Fatal(err)
	}
	diff := cmp.Diff("", a.Id)
	if diff != "" {
		t.Error(diff)
	}

	diff = cmp.Diff(int64(0), a.SeqNo)
	if diff != "" {
		t.Error(diff)
	}

	diff = cmp.Diff(int64(0), a.Version)
	if diff != "" {
		t.Error(diff)
	}

	hit := HitT{
		ID:      action.Id,
		SeqNo:   action.SeqNo,
		Version: action.Version,
		Source:  body,
	}

	var actionFromHit model.Action

	err = hit.Unmarshal(&actionFromHit)
	if err != nil {
		t.Fatal(err)
	}

	diff = cmp.Diff(action, actionFromHit)
	if diff != "" {
		t.Error(diff)
	}

}
