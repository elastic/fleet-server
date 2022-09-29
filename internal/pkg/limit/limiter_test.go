// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package limit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"
)

type mockIncer struct {
	mock.Mock
}

func (m *mockIncer) IncError(err error) {
	m.Called(err)
}

func (m *mockIncer) IncStart() func() {
	args := m.Called()
	return args.Get(0).(func())
}

func stubHandle() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.WriteHeader(http.StatusOK)
	}
}

func TestWrap(t *testing.T) {
	t.Run("no limits reached", func(t *testing.T) {
		var b bool
		var fdec = func() { b = true }
		i := &mockIncer{}
		i.On("IncStart").Return(fdec).Once()
		l := &limiter{}

		h := l.wrap(zerolog.Nop(), zerolog.DebugLevel, stubHandle(), i)
		w := httptest.NewRecorder()
		h(w, &http.Request{}, httprouter.Params{})

		resp := w.Result()
		resp.Body.Close()
		i.AssertExpectations(t)
		assert.True(t, b, "expected dec func to have been called")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
	t.Run("max limit reached", func(t *testing.T) {
		var b bool
		var fdec = func() { b = true }
		i := &mockIncer{}
		i.On("IncStart").Return(fdec).Once()
		i.On("IncError", ErrMaxLimit).Once()
		l := &limiter{
			maxLimit: semaphore.NewWeighted(0),
		}

		h := l.wrap(zerolog.Nop(), zerolog.DebugLevel, stubHandle(), i)
		w := httptest.NewRecorder()
		h(w, &http.Request{}, httprouter.Params{})

		resp := w.Result()
		resp.Body.Close()
		i.AssertExpectations(t)
		assert.True(t, b, "expected dec func to have been called")
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	})
	t.Run("rate limit reached", func(t *testing.T) {
		var b bool
		var fdec = func() { b = true }
		i := &mockIncer{}
		i.On("IncStart").Return(fdec).Once()
		i.On("IncError", ErrRateLimit).Once()
		l := &limiter{
			rateLimit: rate.NewLimiter(rate.Limit(0), 0),
		}

		h := l.wrap(zerolog.Nop(), zerolog.DebugLevel, stubHandle(), i)
		w := httptest.NewRecorder()
		h(w, &http.Request{}, httprouter.Params{})

		resp := w.Result()
		resp.Body.Close()
		i.AssertExpectations(t)
		assert.True(t, b, "expected dec func to have been called")
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	})
}
