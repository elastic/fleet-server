// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package action

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/time/rate"
)

type mockMonitor struct {
	mock.Mock
}

func (m *mockMonitor) Output() <-chan []es.HitT {
	args := m.Called()
	return args.Get(0).(<-chan []es.HitT)
}

func (m *mockMonitor) Run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockMonitor) GetCheckpoint() sqn.SeqNo {
	args := m.Called()
	return args.Get(0).(sqn.SeqNo)
}

func TestNewDispatcher(t *testing.T) {
	m := &mockMonitor{}
	d := NewDispatcher(m, 0, 0)

	assert.NotNil(t, d.am)
	assert.NotNil(t, d.subs)
}

func compareActions(t *testing.T, expects, results []model.Action) {
	t.Helper()
	assert.Equal(t, len(expects), len(results))
	for i, expect := range expects {
		result := results[i]
		assert.Equal(t, expect.Id, result.Id)
		assert.Equal(t, expect.Version, result.Version)
		assert.Equal(t, expect.SeqNo, result.SeqNo)
		assert.Equal(t, expect.ActionID, result.ActionID)
		assert.Equal(t, expect.Agents, result.Agents)
		assert.Equal(t, expect.Data, result.Data)
		assert.Equal(t, expect.Expiration, result.Expiration)
		assert.Equal(t, expect.InputType, result.InputType)
		assert.Equal(t, expect.RolloutDurationSeconds, result.RolloutDurationSeconds)
		assert.Equal(t, expect.StartTime, result.StartTime)
		assert.Equal(t, expect.Timeout, result.Timeout)
		assert.Equal(t, expect.Type, result.Type)
		assert.Equal(t, expect.UserID, result.UserID)
	}
}

func Test_Dispatcher_Run(t *testing.T) {
	tests := []struct {
		name     string
		throttle time.Duration
		getMock  func() *mockMonitor
		expect   map[string][]model.Action
	}{{
		name: "one agent action",
		getMock: func() *mockMonitor {
			m := &mockMonitor{}
			ch := make(chan []es.HitT)
			go func() {
				ch <- []es.HitT{es.HitT{
					Source: json.RawMessage(`{"action_id":"test-action","agents":["agent1"],"data":{"key":"value"},"type":"upgrade"}`),
				}}
			}()
			var rch <-chan []es.HitT = ch
			m.On("Output").Return(rch)
			return m
		},
		expect: map[string][]model.Action{
			"agent1": []model.Action{model.Action{
				ActionID: "test-action",
				Agents:   nil,
				Data:     json.RawMessage(`{"key":"value"}`),
				Type:     "upgrade",
			}},
		},
	}, {
		name: "three agent action",
		getMock: func() *mockMonitor {
			m := &mockMonitor{}
			ch := make(chan []es.HitT)
			go func() {
				ch <- []es.HitT{es.HitT{
					Source: json.RawMessage(`{"action_id":"test-action","agents":["agent1","agent2","agent3"],"data":{"key":"value"},"type":"upgrade"}`),
				}}
			}()
			var rch <-chan []es.HitT = ch
			m.On("Output").Return(rch)
			return m
		},
		expect: map[string][]model.Action{
			"agent1": []model.Action{model.Action{
				ActionID: "test-action",
				Agents:   nil,
				Data:     json.RawMessage(`{"key":"value"}`),
				Type:     "upgrade",
			}},
			"agent2": []model.Action{model.Action{
				ActionID: "test-action",
				Agents:   nil,
				Data:     json.RawMessage(`{"key":"value"}`),
				Type:     "upgrade",
			}},
			"agent3": []model.Action{model.Action{
				ActionID: "test-action",
				Agents:   nil,
				Data:     json.RawMessage(`{"key":"value"}`),
				Type:     "upgrade",
			}},
		},
	}, {
		name:     "three agent action with limiter",
		throttle: 1 * time.Second,
		getMock: func() *mockMonitor {
			m := &mockMonitor{}
			ch := make(chan []es.HitT)
			go func() {
				ch <- []es.HitT{es.HitT{
					Source: json.RawMessage(`{"action_id":"test-action","agents":["agent1","agent2","agent3"],"data":{"key":"value"},"type":"upgrade"}`),
				}}
			}()
			var rch <-chan []es.HitT = ch
			m.On("Output").Return(rch)
			return m
		},
		expect: map[string][]model.Action{
			"agent1": []model.Action{model.Action{
				ActionID: "test-action",
				Agents:   nil,
				Data:     json.RawMessage(`{"key":"value"}`),
				Type:     "upgrade",
			}},
			"agent2": []model.Action{model.Action{
				ActionID: "test-action",
				Agents:   nil,
				Data:     json.RawMessage(`{"key":"value"}`),
				Type:     "upgrade",
			}},
			"agent3": []model.Action{model.Action{
				ActionID: "test-action",
				Agents:   nil,
				Data:     json.RawMessage(`{"key":"value"}`),
				Type:     "upgrade",
			}},
		},
	}, {
		name: "one agent action with scheduling",
		getMock: func() *mockMonitor {
			m := &mockMonitor{}
			ch := make(chan []es.HitT)
			go func() {
				ch <- []es.HitT{es.HitT{
					Source: json.RawMessage(`{"action_id":"test-action","agents":["agent1"],"data":{"key":"value"},"expiration":"2022-01-02T13:00:00Z","rollout_duration_seconds":600,"start_time":"2022-01-02T12:00:00Z","type":"upgrade"}`),
				}}
			}()
			var rch <-chan []es.HitT = ch
			m.On("Output").Return(rch)
			return m
		},
		expect: map[string][]model.Action{
			"agent1": []model.Action{model.Action{
				ActionID:               "test-action",
				Agents:                 nil,
				Data:                   json.RawMessage(`{"key":"value"}`),
				Expiration:             "2022-01-02T13:00:00Z",
				RolloutDurationSeconds: 600,
				StartTime:              "2022-01-02T12:00:00Z",
				Type:                   "upgrade",
			}},
		},
	}, {
		name: "three agent action with scheduling",
		getMock: func() *mockMonitor {
			m := &mockMonitor{}
			ch := make(chan []es.HitT)
			go func() {
				ch <- []es.HitT{es.HitT{
					Source: json.RawMessage(`{"action_id":"test-action","agents":["agent1","agent2","agent3"],"data":{"key":"value"},"expiration":"2022-01-02T13:00:00Z","rollout_duration_seconds":600,"start_time":"2022-01-02T12:00:00Z","type":"upgrade"}`),
				}}
			}()
			var rch <-chan []es.HitT = ch
			m.On("Output").Return(rch)
			return m
		},
		expect: map[string][]model.Action{
			"agent1": []model.Action{model.Action{
				ActionID:               "test-action",
				Agents:                 nil,
				Data:                   json.RawMessage(`{"key":"value"}`),
				Expiration:             "2022-01-02T13:00:00Z",
				RolloutDurationSeconds: 600,
				StartTime:              "2022-01-02T12:00:00Z",
				Type:                   "upgrade",
			}},
			"agent2": []model.Action{model.Action{
				ActionID:               "test-action",
				Agents:                 nil,
				Data:                   json.RawMessage(`{"key":"value"}`),
				Expiration:             "2022-01-02T13:00:00Z",
				RolloutDurationSeconds: 600,
				StartTime:              "2022-01-02T12:03:20Z",
				Type:                   "upgrade",
			}},
			"agent3": []model.Action{model.Action{
				ActionID:               "test-action",
				Agents:                 nil,
				Data:                   json.RawMessage(`{"key":"value"}`),
				Expiration:             "2022-01-02T13:00:00Z",
				RolloutDurationSeconds: 600,
				StartTime:              "2022-01-02T12:06:40Z",
				Type:                   "upgrade",
			}},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.getMock()
			throttle := rate.Inf
			if tt.throttle > 0 {
				throttle = rate.Every(tt.throttle)
			}
			d := &Dispatcher{
				am:    m,
				limit: rate.NewLimiter(throttle, 1),
				subs: map[string]Sub{
					"agent1": Sub{
						agentID: "agent1",
						ch:      make(chan []model.Action, 1),
					},
					"agent2": Sub{
						agentID: "agent2",
						ch:      make(chan []model.Action, 1),
					},
					"agent3": Sub{
						agentID: "agent3",
						ch:      make(chan []model.Action, 1),
					},
				},
			}

			now := time.Now()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				err := d.Run(ctx)
				assert.Nil(t, err)
			}()

			ticker := time.NewTicker(time.Second * 5)

			select {
			case actions := <-d.subs["agent1"].Ch():
				compareActions(t, tt.expect["agent1"], actions)
				// NOTE: agent1 is not rate limited if the action limmiter is enabled for these tests.
			case <-ticker.C:
				t.Fatal("timeout waiting for subscription on agent1")
			}

			if expect, ok := tt.expect["agent2"]; ok {
				ticker.Reset(time.Second * 5)
				select {
				case actions := <-d.subs["agent2"].Ch():
					compareActions(t, expect, actions)
					if tt.throttle != 0 {
						assert.GreaterOrEqual(t, time.Now(), now.Add(1*tt.throttle))
					}
				case <-ticker.C:
					t.Fatal("timeout waiting for subscription on agent2")
				}
			}

			if expect, ok := tt.expect["agent3"]; ok {
				ticker.Reset(time.Second * 5)
				select {
				case actions := <-d.subs["agent3"].Ch():
					compareActions(t, expect, actions)
					if tt.throttle != 0 {
						assert.GreaterOrEqual(t, time.Now(), now.Add(2*tt.throttle))
					}
				case <-ticker.C:
					t.Fatal("timeout waiting for subscription on agent3")
				}
			}

		})
	}
}

func Test_offsetStartTime(t *testing.T) {
	tests := []struct {
		name   string
		start  string
		end    string
		dur    int64
		i      int
		total  int
		result string
	}{{
		name:   "no start",
		result: "",
	}, {
		name:   "first agent",
		start:  "2022-01-02T12:00:00Z",
		end:    "2022-01-02T13:00:00Z",
		i:      0,
		total:  10,
		result: "2022-01-02T12:00:00Z",
	}, {
		name:   "mid agent no dur",
		start:  "2022-01-02T12:00:00Z",
		end:    "2022-01-02T13:00:00Z",
		i:      4,
		total:  10,
		result: "2022-01-02T12:00:00Z",
	}, {
		name:   "last agent no dur",
		start:  "2022-01-02T12:00:00Z",
		end:    "2022-01-02T13:00:00Z",
		i:      9,
		total:  10,
		result: "2022-01-02T12:00:00Z",
	}, {
		name:   "first agent 10m dur",
		start:  "2022-01-02T12:00:00Z",
		end:    "2022-01-02T13:00:00Z",
		dur:    600,
		i:      0,
		total:  10,
		result: "2022-01-02T12:00:00Z",
	}, {
		name:   "mid agent 10m dur",
		start:  "2022-01-02T12:00:00Z",
		end:    "2022-01-02T13:00:00Z",
		dur:    600,
		i:      4,
		total:  10,
		result: "2022-01-02T12:04:00Z",
	}, {
		name:   "last agent 10m dur",
		start:  "2022-01-02T12:00:00Z",
		end:    "2022-01-02T13:00:00Z",
		dur:    600,
		i:      9,
		total:  10,
		result: "2022-01-02T12:09:00Z",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := offsetStartTime(tt.start, tt.dur, tt.i, tt.total)
			assert.Equal(t, tt.result, r)
		})
	}
}
