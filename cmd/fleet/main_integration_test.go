// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

//nolint:unused // some unused code may be added to more tests
package fleet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/client/mock"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/go-ucfg"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

var biInfo = build.Info{
	Version: "1.0.0",
	Commit:  "integration",
}

var policyData = []byte(`
{
	"outputs": {
		"default": {
			"type": "elasticsearch"
		}
	},
	"inputs": [
		{
			"type": "fleet-server"
		}
	]
}
`)

func TestAgentMode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bulker := ftesting.SetupBulk(ctx, t)

	// add a real default fleet server policy
	policyID := uuid.Must(uuid.NewV4()).String()
	_, err := dl.CreatePolicy(ctx, bulker, model.Policy{
		PolicyID:           policyID,
		RevisionIdx:        1,
		DefaultFleetServer: true,
		Data:               policyData,
	})
	require.NoError(t, err)

	// add entry for enrollment key (doesn't have to be a real key)
	_, err = dl.CreateEnrollmentAPIKey(ctx, bulker, model.EnrollmentAPIKey{
		Name:     "Default",
		APIKey:   "keyvalue",
		APIKeyID: "keyid",
		PolicyID: policyID,
		Active:   true,
	})
	require.NoError(t, err)

	inputSource, err := structpb.NewStruct(map[string]interface{}{
		"id":       "fleet-server",
		"type":     "fleet-server",
		"name":     "fleet-server",
		"revision": 1,
	})
	require.NoError(t, err)
	outputSource, err := structpb.NewStruct(map[string]interface{}{
		"id":            "default",
		"type":          "elasticsearch",
		"name":          "elasticsearch",
		"revision":      1,
		"hosts":         getESHosts(),
		"service_token": getESServiceToken(),
	})
	require.NoError(t, err)
	expected := makeExpected("", 1, inputSource, 1, outputSource)
	control := createAndStartControlServer(t, expected)
	defer control.Stop()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		a := &AgentMode{
			cliCfg: ucfg.New(),
			bi:     biInfo,
		}
		a.agent = client.NewV2(fmt.Sprintf("localhost:%d", control.Port()), control.Token(), client.VersionInfo{
			Name:    "fleet-server",
			Version: "1.0.0",
		}, grpc.WithTransportCredentials(insecure.NewCredentials()))
		err = a.Run(ctx)
		assert.NoError(t, err)
	}()

	// wait for fleet-server to report as degraded (starting mode without agent.id)
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state := getUnitState(control, proto.UnitType_INPUT, "fleet-server-default-fleet-server")
		if state != proto.State_DEGRADED {
			return fmt.Errorf("should be reported as degraded; instead its %s", state)
		}
		return nil
	}, ftesting.RetrySleep(100*time.Millisecond), ftesting.RetryCount(120))

	// reconfigure with agent ID set
	agentID := uuid.Must(uuid.NewV4()).String()
	expected = makeExpected(agentID, 1, inputSource, 1, outputSource)
	control.Expected(expected)
	require.NoError(t, err)

	// wait for fleet-server to report as healthy
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state := getUnitState(control, proto.UnitType_INPUT, "fleet-server-default-fleet-server")
		if state != proto.State_HEALTHY {
			return fmt.Errorf("should be reported as healthy; instead its %s", state)
		}
		return nil
	}, ftesting.RetrySleep(100*time.Millisecond), ftesting.RetryCount(120))

	// trigger update with bad configuration
	badSource, err := structpb.NewStruct(map[string]interface{}{
		"id":            "default",
		"type":          "elasticsearch",
		"name":          "elasticsearch",
		"revision":      1,
		"hosts":         []interface{}{"localhost:63542"},
		"service_token": getESServiceToken(),
	})
	require.NoError(t, err)
	expected = makeExpected(agentID, 1, inputSource, 2, badSource)
	control.Expected(expected)

	// wait for fleet-server to report as failed
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state := getUnitState(control, proto.UnitType_INPUT, "fleet-server-default-fleet-server")
		if state != proto.State_FAILED {
			return fmt.Errorf("should be reported as failed; instead its %s", state)
		}
		return nil
	}, ftesting.RetrySleep(100*time.Millisecond), ftesting.RetryCount(120))

	// reconfigure to good config
	goodSource, err := structpb.NewStruct(map[string]interface{}{
		"id":            "default",
		"type":          "elasticsearch",
		"name":          "elasticsearch",
		"revision":      1,
		"hosts":         getESHosts(),
		"service_token": getESServiceToken(),
	})
	require.NoError(t, err)
	expected = makeExpected(agentID, 1, inputSource, 3, goodSource)
	control.Expected(expected)

	// wait for fleet-server to report as healthy
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state := getUnitState(control, proto.UnitType_INPUT, "fleet-server-default-fleet-server")
		if state != proto.State_HEALTHY {
			return fmt.Errorf("should be reported as healthy; instead its %s", state)
		}
		return nil
	}, ftesting.RetrySleep(100*time.Millisecond), ftesting.RetryCount(120))

	// trigger stop
	expected = makeExpected(agentID, 1, inputSource, 3, outputSource)
	expected.Units[0].State = proto.State_STOPPED
	expected.Units[1].State = proto.State_STOPPED
	control.Expected(expected)

	// wait for fleet-server to report as stopped
	ftesting.Retry(t, ctx, func(ctx context.Context) error {
		state := getUnitState(control, proto.UnitType_INPUT, "fleet-server-default-fleet-server")
		if state != proto.State_STOPPED {
			return fmt.Errorf("should be reported as stopped; instead its %s", state)
		}
		return nil
	}, ftesting.RetrySleep(100*time.Millisecond), ftesting.RetryCount(120))

	// stop the agent and wait for go routine to exit
	cancel()
	wg.Wait()
}

func createAndStartControlServer(t *testing.T, expected *proto.CheckinExpected) *StubV2Control {
	t.Helper()

	srv := NewStubV2Control(expected)
	require.NoError(t, srv.Start())
	return srv
}

type StubV2Control struct {
	proto.UnimplementedElasticAgentServer

	token string
	port  int

	server *grpc.Server

	mx        sync.Mutex
	observed  *proto.CheckinObserved
	expected  *proto.CheckinExpected
	forceSend chan struct{}
}

func NewStubV2Control(expected *proto.CheckinExpected) *StubV2Control {
	token := mock.NewID()
	s := &StubV2Control{
		token:     token,
		expected:  expected,
		forceSend: make(chan struct{}),
	}
	return s
}

func (s *StubV2Control) Token() string {
	return s.token
}

func (s *StubV2Control) Port() int {
	return s.port
}

func (s *StubV2Control) Start(opt ...grpc.ServerOption) error {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		return err
	}
	s.port = lis.Addr().(*net.TCPAddr).Port
	srv := grpc.NewServer(opt...)
	s.server = srv
	proto.RegisterElasticAgentServer(s.server, s)
	go func() {
		srv.Serve(lis)
	}()
	return nil
}

func (s *StubV2Control) Stop() {
	if s.server != nil {
		s.server.Stop()
		s.server = nil
	}
}

func (s *StubV2Control) Expected(expected *proto.CheckinExpected) {
	s.mx.Lock()
	s.expected = expected
	s.mx.Unlock()
	s.forceSend <- struct{}{}
}

func (s *StubV2Control) Observed() *proto.CheckinObserved {
	s.mx.Lock()
	defer s.mx.Unlock()
	return s.observed
}

// Checkin is the checkin implementation for the mock server
func (s *StubV2Control) Checkin(server proto.ElasticAgent_CheckinServer) error {
	return errors.New("no V1 support")
}

// CheckinV2 is the V2 checkin implementation for the mock server
func (s *StubV2Control) CheckinV2(server proto.ElasticAgent_CheckinV2Server) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.forceSend:
				s.mx.Lock()
				expected := s.expected
				s.mx.Unlock()
				_ = server.Send(expected)
			}
		}
	}()

	for {
		checkin, err := server.Recv()
		if err != nil {
			return err
		}
		if checkin.Token != s.token {
			return errors.New("invalid token")
		}

		s.mx.Lock()
		s.observed = checkin
		expected := s.expected
		s.mx.Unlock()

		err = server.Send(expected)
		if err != nil {
			return err
		}
	}
}

// Actions is the action implementation for the mock server
func (s *StubV2Control) Actions(server proto.ElasticAgent_ActionsServer) error {
	return nil
}

func getESHosts() []interface{} {
	hosts := os.Getenv("ELASTICSEARCH_HOSTS")
	if hosts == "" {
		return []interface{}{"localhost:9200"}
	}
	hostsSplit := strings.Split(hosts, ",")
	rawHosts := make([]interface{}, 0, len(hostsSplit))
	for _, host := range hostsSplit {
		rawHosts = append(rawHosts, host)
	}
	return rawHosts
}

func getESServiceToken() string {
	return os.Getenv("ELASTICSEARCH_SERVICE_TOKEN")
}

func getUnitState(control *StubV2Control, unitType proto.UnitType, unitID string) proto.State {
	obs := control.Observed()
	if obs == nil {
		return proto.State_STARTING
	}
	for _, unit := range obs.Units {
		if unit.Type == unitType && unit.Id == unitID {
			return unit.State
		}
	}
	return proto.State_STARTING
}

func makeExpected(agentID string, inputConfigIdx uint64, inputSource *structpb.Struct, outputConfigIdx uint64, outputSource *structpb.Struct) *proto.CheckinExpected {
	return &proto.CheckinExpected{
		AgentInfo: &proto.CheckinAgentInfo{
			Id:       agentID,
			Version:  "8.5.0",
			Snapshot: true,
		},
		Units: []*proto.UnitExpected{
			{
				Id:             "fleet-server-default-fleet-server",
				Type:           proto.UnitType_INPUT,
				State:          proto.State_HEALTHY,
				ConfigStateIdx: inputConfigIdx,
				Config: &proto.UnitExpectedConfig{
					Source:   inputSource,
					Id:       "fleet-server",
					Type:     "fleet-server",
					Name:     "Fleet Server",
					Revision: 1,
				},
				LogLevel: proto.UnitLogLevel_INFO,
			},
			{
				Id:             "fleet-server-default",
				Type:           proto.UnitType_OUTPUT,
				State:          proto.State_HEALTHY,
				ConfigStateIdx: outputConfigIdx,
				Config: &proto.UnitExpectedConfig{
					Source:   outputSource,
					Id:       "default",
					Type:     "elasticsearch",
					Name:     "elasticsearch",
					Revision: 1,
				},
				LogLevel: proto.UnitLogLevel_INFO,
			},
		},
	}
}
