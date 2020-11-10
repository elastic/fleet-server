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

package rate

// Listener limited by leaky bucket.
// TODO: Not enamored with this.  More complicated than necessary.

import (
	"context"
	"net"
	"time"

	xr "golang.org/x/time/rate"
)

type rateListener struct {
	net.Listener
	lim *xr.Limiter

	ctx     context.Context
	cancelF context.CancelFunc
}

func NewRateListener(ctx context.Context, l net.Listener, burst int, interval time.Duration) net.Listener {

	ctx, cfunc := context.WithCancel(ctx)

	return &rateListener{
		Listener: l,
		lim:      xr.NewLimiter(xr.Every(interval), burst),
		ctx:      ctx,
		cancelF:  cfunc,
	}
}

func (r *rateListener) Accept() (net.Conn, error) {
	if err := r.lim.Wait(r.ctx); err != nil {
		return nil, err
	}

	return r.Listener.Accept()
}

func (r *rateListener) Close() error {
	r.cancelF()
	return r.Listener.Close()
}
