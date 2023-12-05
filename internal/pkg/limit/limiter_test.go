// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package limit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"
)

type mockIncer struct {
	mock.Mock
}

func (m *mockIncer) IncError(err error, attrs ...attribute.KeyValue) {
	m.Called(err, attrs)
}

func (m *mockIncer) IncStart(attrs ...attribute.KeyValue) func() {
	args := m.Called(attrs)
	return args.Get(0).(func())
}

func stubHandle() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func Test_Limiter_Wrap(t *testing.T) {
	tests := []struct {
		name   string
		l      *Limiter
		stats  func() *mockIncer
		status int
	}{{
		name: "no limits",
		l:    &Limiter{},
		stats: func() *mockIncer {
			m := &mockIncer{}
			m.On("IncStart", mock.Anything).Return(noop).Once()
			return m
		},
		status: http.StatusOK,
	}, {
		name: "max limit",
		l: &Limiter{
			maxLimit: semaphore.NewWeighted(0),
		},
		stats: func() *mockIncer {
			m := &mockIncer{}
			m.On("IncStart", mock.Anything).Return(noop).Once()
			m.On("IncError", ErrMaxLimit, mock.Anything).Once()
			return m
		},
		status: http.StatusTooManyRequests,
	}, {
		name: "rate limit",
		l: &Limiter{
			rateLimit: rate.NewLimiter(rate.Limit(0), 0),
		},
		stats: func() *mockIncer {
			m := &mockIncer{}
			m.On("IncStart", mock.Anything).Return(noop).Once()
			m.On("IncError", ErrRateLimit, mock.Anything).Once()
			return m
		},
		status: http.StatusTooManyRequests,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := tt.stats()
			h := tt.l.Wrap("name", mi, zerolog.DebugLevel)

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "http://example.com", nil)
			h(stubHandle()).ServeHTTP(w, req)

			resp := w.Result()
			resp.Body.Close()
			assert.Equal(t, tt.status, resp.StatusCode)
			mi.AssertExpectations(t)
		})
	}
}
