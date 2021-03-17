// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/julienschmidt/httprouter"
)

const (
	ROUTE_STATUS  = "/api/status"
	ROUTE_ENROLL  = "/api/fleet/agents/:id"
	ROUTE_CHECKIN = "/api/fleet/agents/:id/checkin"
	ROUTE_ACKS    = "/api/fleet/agents/:id/acks"
)

type Router struct {
	bulker bulk.Bulk
	ver    string
	ct     *CheckinT
	et     *EnrollerT
	sm     policy.SelfMonitor
}

func NewRouter(bulker bulk.Bulk, ct *CheckinT, et *EnrollerT, sm policy.SelfMonitor) *httprouter.Router {

	r := Router{
		bulker: bulker,
		ct:     ct,
		et:     et,
		sm:     sm,
	}

	router := httprouter.New()
	router.GET(ROUTE_STATUS, r.handleStatus)
	router.POST(ROUTE_ENROLL, r.handleEnroll)
	router.POST(ROUTE_CHECKIN, r.handleCheckin)
	router.POST(ROUTE_ACKS, r.handleAcks)
	return router
}
