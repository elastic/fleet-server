// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build !integration

package fleet

import (
	"context"
	"fleet/internal/pkg/config"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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

	bulker := ftesting.MockBulk{}
	sv := saved.NewMgr(bulker, savedObjectKey())
	pm, err := NewPolicyMon(kPolicyThrottle)
	require.NoError(t, err)
	ba := NewBulkActions()
	bc := NewBulkCheckin(nil)
	ct := NewCheckinT(nil, bc, ba, pm, nil, nil, nil, nil)
	et := NewEnrollerT(cfg, nil)

	router := NewRouter(sv, bulker, ct, et)
	errCh := make(chan error)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		err = runServer(ctx, router, cfg)
		wg.Done()
	}()
	var errFromChan error
	select {
	case err := <-errCh:
		errFromChan = err
	case <-time.After(500 * time.Millisecond):
		break
	}
	cancel()
	wg.Wait()
	require.NoError(t, errFromChan)
	if err != http.ErrServerClosed {
		require.NoError(t, err)
	}
}
