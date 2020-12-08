// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/saved"

	"github.com/julienschmidt/httprouter"
)

const (
	ROUTE_ENROLL  = "/api/fleet/agents/:id"
	ROUTE_CHECKIN = "/api/fleet/agents/:id/checkin"
	ROUTE_ACKS    = "/api/fleet/agents/:id/acks"
)

type Router struct {
	sv     saved.CRUD
	bulker bulk.Bulk
	ct     *CheckinT
	et     *EnrollerT
}

func NewRouter(sv saved.CRUD, bulker bulk.Bulk, ct *CheckinT, et *EnrollerT) *httprouter.Router {

	r := Router{
		sv:     sv,
		bulker: bulker,
		ct:     ct,
		et:     et,
	}

	router := httprouter.New()
	router.POST(ROUTE_ENROLL, r.handleEnroll)
	router.POST(ROUTE_CHECKIN, r.handleCheckin)
	router.POST(ROUTE_ACKS, r.handleAcks)
	return router
}
