// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"context"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
)

// The ApiKey API's are not yet bulk enabled. Stub the calls in the bulker
// and limit parallel access to prevent many requests from overloading
// the connection pool in the elastic search client.

func (b *Bulker) APIKeyAuth(ctx context.Context, key APIKey) (*SecurityInfo, error) {
	if err := b.apikeyLimit.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer b.apikeyLimit.Release(1)

	return key.Authenticate(ctx, b.Client())
}

func (b *Bulker) APIKeyCreate(ctx context.Context, name, ttl string, roles []byte, meta interface{}) (*APIKey, error) {
	if err := b.apikeyLimit.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer b.apikeyLimit.Release(1)

	return apikey.Create(ctx, b.Client(), name, ttl, "false", roles, meta)
}

func (b *Bulker) APIKeyRead(ctx context.Context, id string) (*APIKeyMetadata, error) {
	if err := b.apikeyLimit.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer b.apikeyLimit.Release(1)

	return apikey.Read(ctx, b.Client(), id)
}

func (b *Bulker) APIKeyInvalidate(ctx context.Context, ids ...string) error {
	if err := b.apikeyLimit.Acquire(ctx, 1); err != nil {
		return err
	}
	defer b.apikeyLimit.Release(1)

	return apikey.Invalidate(ctx, b.Client(), ids...)
}
