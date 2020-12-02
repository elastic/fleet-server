// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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
