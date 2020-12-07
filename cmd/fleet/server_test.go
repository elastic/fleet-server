// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"fleet/internal/pkg/config"
	"github.com/stretchr/testify/require"
	"net/http"
	"sync"
	"testing"
	"time"

	"fleet/internal/pkg/saved"
	ftesting "fleet/internal/pkg/testing"
)

func TestRunServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port, err := ftesting.FreePort()
	require.NoError(t, err)
	cfg := &config.Server{}
	cfg.InitDefaults()
	cfg.Host = "localhost"
	cfg.Port = port

	sv := saved.NewMgr(ftesting.MockBulk{}, savedObjectKey())
	pm, err := NewPolicyMon(kPolicyThrottle)
	require.NoError(t, err)
	ba := NewBulkActions()
	bc := NewBulkCheckin()
	ct := NewCheckinT(bc, ba, pm)
	et := NewEnrollerT(cfg)

	router := NewRouter(sv, ct, et)
	errCh := make(chan error)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		err = runServer(ctx, router, cfg, errCh)
		wg.Done()
	}()
	select {
	case errFromChan := <-errCh:
		err = errFromChan
	case <-time.After(500 * time.Millisecond):
		break
	}
	cancel()
	wg.Wait()
	if err != http.ErrServerClosed && err != context.Canceled {
		require.NoError(t, err)
	}
}
