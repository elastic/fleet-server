// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package main

import (
	"context"
	"fleet/internal/pkg/saved"

	"github.com/julienschmidt/httprouter"
)

const (
	ROUTE_ENROLL  = "/api/fleet/agents/:id"
	ROUTE_CHECKIN = "/api/fleet/agents/:id/checkin"
	ROUTE_ACKS    = "/api/fleet/agents/:id/acks"
)

type Router struct {
	sv saved.CRUD
	ct *CheckinT
	et *EnrollerT
}

func NewRouter(ctx context.Context, sv saved.CRUD, ct *CheckinT, et *EnrollerT) *httprouter.Router {

	r := Router{
		sv: sv,
		ct: ct,
		et: et,
	}

	router := httprouter.New()
	router.POST(ROUTE_ENROLL, r.handleEnroll)
	router.POST(ROUTE_CHECKIN, r.handleCheckin)
	router.POST(ROUTE_ACKS, r.handleAcks)
	return router
}
