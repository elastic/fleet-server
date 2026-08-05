// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package action

import (
	"context"
	"errors"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestTokenResolverResolve_CacheHit(t *testing.T) {
	bulker := ftesting.NewMockBulk()
	tr, err := NewTokenResolver(bulker)
	require.NoError(t, err)

	tr.cache.Add("tok1", int64(42))

	seqno, err := tr.Resolve(context.Background(), "tok1")
	assert.NoError(t, err)
	assert.Equal(t, int64(42), seqno)
	bulker.AssertNotCalled(t, "Search", mock.Anything, mock.Anything, mock.Anything)
}

func TestTokenResolverResolve_EmptyToken(t *testing.T) {
	bulker := ftesting.NewMockBulk()
	tr, err := NewTokenResolver(bulker)
	require.NoError(t, err)

	_, err = tr.Resolve(context.Background(), "")
	assert.ErrorIs(t, err, dl.ErrNotFound)
}

func TestTokenResolverResolve_IndexNotFound(t *testing.T) {
	bulker := ftesting.NewMockBulk()
	bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&es.ResultT{}, es.ErrIndexNotFound)

	tr, err := NewTokenResolver(bulker)
	require.NoError(t, err)

	_, err = tr.Resolve(context.Background(), "tok1")
	assert.ErrorIs(t, err, dl.ErrNotFound)
}

func TestTokenResolverResolve_OtherError(t *testing.T) {
	bulker := ftesting.NewMockBulk()
	someErr := errors.New("connection refused")
	bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&es.ResultT{}, someErr)

	tr, err := NewTokenResolver(bulker)
	require.NoError(t, err)

	_, err = tr.Resolve(context.Background(), "tok1")
	assert.ErrorIs(t, err, someErr)
}
