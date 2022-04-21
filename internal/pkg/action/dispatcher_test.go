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
	d := NewDispatcher(m)

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
		assert.Equal(t, expect.MinimumExecutionDuration, result.MinimumExecutionDuration)
		assert.Equal(t, expect.StartTime, result.StartTime)
		assert.Equal(t, expect.Timeout, result.Timeout)
		assert.Equal(t, expect.Type, result.Type)
		assert.Equal(t, expect.UserID, result.UserID)
	}
}

func Test_Dispatcher_Run(t *testing.T) {
	tests := []struct {
		name    string
		getMock func() *mockMonitor
		expect  map[string][]model.Action
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
		name: "one agent action with scheduling",
		getMock: func() *mockMonitor {
			m := &mockMonitor{}
			ch := make(chan []es.HitT)
			go func() {
				ch <- []es.HitT{es.HitT{
					Source: json.RawMessage(`{"action_id":"test-action","agents":["agent1"],"data":{"key":"value"},"expiration":"2022-01-02T13:00:00Z","minimum_execution_duration":"10m","start_time":"2022-01-02T12:00:00Z","type":"upgrade"}`),
				}}
			}()
			var rch <-chan []es.HitT = ch
			m.On("Output").Return(rch)
			return m
		},
		expect: map[string][]model.Action{
			"agent1": []model.Action{model.Action{
				ActionID:                 "test-action",
				Agents:                   nil,
				Data:                     json.RawMessage(`{"key":"value"}`),
				Expiration:               "2022-01-02T13:00:00Z",
				MinimumExecutionDuration: "10m",
				StartTime:                "2022-01-02T12:00:00Z",
				Type:                     "upgrade",
			}},
		},
	}, {
		name: "three agent action with scheduling",
		getMock: func() *mockMonitor {
			m := &mockMonitor{}
			ch := make(chan []es.HitT)
			go func() {
				ch <- []es.HitT{es.HitT{
					Source: json.RawMessage(`{"action_id":"test-action","agents":["agent1","agent2","agent3"],"data":{"key":"value"},"expiration":"2022-01-02T13:00:00Z","minimum_execution_duration":"10m","start_time":"2022-01-02T12:00:00Z","type":"upgrade"}`),
				}}
			}()
			var rch <-chan []es.HitT = ch
			m.On("Output").Return(rch)
			return m
		},
		expect: map[string][]model.Action{
			"agent1": []model.Action{model.Action{
				ActionID:                 "test-action",
				Agents:                   nil,
				Data:                     json.RawMessage(`{"key":"value"}`),
				Expiration:               "2022-01-02T13:00:00Z",
				MinimumExecutionDuration: "10m",
				StartTime:                "2022-01-02T12:00:00Z",
				Type:                     "upgrade",
			}},
			"agent2": []model.Action{model.Action{
				ActionID:                 "test-action",
				Agents:                   nil,
				Data:                     json.RawMessage(`{"key":"value"}`),
				Expiration:               "2022-01-02T13:00:00Z",
				MinimumExecutionDuration: "10m",
				StartTime:                "2022-01-02T12:16:40Z",
				Type:                     "upgrade",
			}},
			"agent3": []model.Action{model.Action{
				ActionID:                 "test-action",
				Agents:                   nil,
				Data:                     json.RawMessage(`{"key":"value"}`),
				Expiration:               "2022-01-02T13:00:00Z",
				MinimumExecutionDuration: "10m",
				StartTime:                "2022-01-02T12:33:20Z",
				Type:                     "upgrade",
			}},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.getMock()
			d := &Dispatcher{
				am: m,
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
			case <-ticker.C:
				t.Fatal("timeout waiting for subscription on agent1")
			}

			if expect, ok := tt.expect["agent2"]; ok {
				ticker.Reset(time.Second * 5)
				select {
				case actions := <-d.subs["agent2"].Ch():
					compareActions(t, expect, actions)
				case <-ticker.C:
					t.Fatal("timeout waiting for subscription on agent2")
				}
			}

			if expect, ok := tt.expect["agent3"]; ok {
				ticker.Reset(time.Second * 5)
				select {
				case actions := <-d.subs["agent3"].Ch():
					compareActions(t, expect, actions)
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
		dur    string
		i      int
		total  int
		result string
	}{{
		name:   "no start",
		result: "",
	}, {
		name:   "no exp",
		start:  "2022-01-02T12:00:00Z",
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
		result: "2022-01-02T12:24:00Z",
	}, {
		name:   "last agent no dur",
		start:  "2022-01-02T12:00:00Z",
		end:    "2022-01-02T13:00:00Z",
		i:      9,
		total:  10,
		result: "2022-01-02T12:54:00Z",
	}, {
		name:   "first agent 10m dur",
		start:  "2022-01-02T12:00:00Z",
		end:    "2022-01-02T13:00:00Z",
		dur:    "10m",
		i:      0,
		total:  10,
		result: "2022-01-02T12:00:00Z",
	}, {
		name:   "mid agent 10m dur",
		start:  "2022-01-02T12:00:00Z",
		end:    "2022-01-02T13:00:00Z",
		dur:    "10m",
		i:      4,
		total:  10,
		result: "2022-01-02T12:20:00Z",
	}, {
		name:   "last agent 10m dur",
		start:  "2022-01-02T12:00:00Z",
		end:    "2022-01-02T13:00:00Z",
		dur:    "10m",
		i:      9,
		total:  10,
		result: "2022-01-02T12:45:00Z",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := offsetStartTime(tt.start, tt.end, tt.dur, tt.i, tt.total)
			assert.Equal(t, tt.result, r)
		})
	}
}
