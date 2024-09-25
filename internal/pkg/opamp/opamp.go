// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// opamp provides a poc of fleet-server serving the opamp spec
// It can serve new policies

package opamp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
)

const DefaultPath = "/v1/opamp"

var healthToStatus = map[bool]string{
	true:  "healthy",
	false: "unhealthy",
}

const serverCapabilities uint64 = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000020 // status, offers remote config, accepts effective config, offers connection settings

const kFleetAccessRolesJSON = `
{
	"fleet-apikey-access": {
		"cluster": [],
		"applications": [{
			"application": "fleet",
			"privileges": ["no-privileges"],
			"resources": ["*"]
		}]
	}
}
`

type opamp struct {
	bulk  bulk.Bulk
	cache cache.Cache
	pm    policy.Monitor
}

func NewHandler(bulk bulk.Bulk, cache cache.Cache, pm policy.Monitor) *opamp {
	return &opamp{
		bulk:  bulk,
		cache: cache,
		pm:    pm,
	}
}

type processArgs struct {
	agent      *model.Agent
	policyID   string
	namespaces []string
}

type Option func(*processArgs)

func WithAgent(agent *model.Agent) Option {
	return func(p *processArgs) {
		p.agent = agent
	}
}

func WithPolicyID(id string) Option {
	return func(p *processArgs) {
		p.policyID = id
	}
}

func WithNamespaces(namespaces []string) Option {
	return func(p *processArgs) {
		p.namespaces = namespaces
	}
}

// Process handles AgentToServer messages
func (o *opamp) Process(ctx context.Context, message *protobufs.AgentToServer, opts ...Option) (*protobufs.ServerToAgent, error) {
	if message.GetCapabilities()&0x00000001 == 0 { // ReportsStatus must be set on all agents
		return nil, fmt.Errorf("capaability: ReportsStatus is unset")
	}
	args := &processArgs{}
	for _, opt := range opts {
		opt(args)
	}

	if args.agent == nil && args.policyID != "" {
		return o.register(ctx, message, args.policyID, args.namespaces)
	}
	if args.agent.Id != string(message.InstanceUid) {
		return nil, fmt.Errorf("API key's associated agent does not match InstanceUid")
	}
	return o.process(ctx, message, args.agent)
}

// process is a func that is similar to the api checkin path
// it will update health status (but not metadata yet) and dispatch new config
// configs are dispatched if the sent config has a lower revision number than the current policy, or if no config is sent if the agent doc has a lower revision number.
func (o *opamp) process(ctx context.Context, message *protobufs.AgentToServer, agent *model.Agent) (*protobufs.ServerToAgent, error) {
	if agent == nil {
		return nil, fmt.Errorf("no agent record found")
	}
	ts := time.Now().UTC()
	tsStr := ts.Format(time.RFC3339)

	// update the agent description if health status has changed. otherwise just a minimal update
	updateAgent := false
	if health := message.GetHealth(); health != nil && agent.LastCheckinStatus != healthToStatus[health.Healthy] {
		updateAgent = true
	}
	update := bulk.UpdateFields{
		dl.FieldLastCheckin: tsStr,
		dl.FieldUpdatedAt:   tsStr,
	}
	if updateAgent {
		update[dl.FieldLastCheckinStatus] = healthToStatus[message.GetHealth().Healthy]
		update[dl.FieldLastCheckinMessage] = message.GetHealth().Status
		update[dl.FieldComponents] = toComponentList(message.GetHealth().GetComponentHealthMap())
	}
	updateBody, err := update.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal agent update: %w", err)
	}
	if err := o.bulk.Update(ctx, dl.FleetAgents, agent.Id, updateBody); err != nil {
		return nil, fmt.Errorf("failed to update agent doc: %w", err)
	}

	rev := agent.PolicyRevisionIdx
	// use revisionIDx from agent's config if it's sent
	var cfg *protobufs.AgentConfigFile
	ecfg := message.GetEffectiveConfig()
	if ecfg != nil {
		if cm := ecfg.GetConfigMap(); cm != nil {
			if cfile, ok := cm.GetConfigMap()[""]; ok {
				cfg = cfile
			}
		}
	}
	if len(cfg.Body) > 0 {
		switch cfg.ContentType {
		case "application/json":
			var policy model.Policy
			if err := json.Unmarshal(cfg.Body, &policy); err != nil {
				return nil, fmt.Errorf("unmarshal effective policy failed: %w", err)
			}
			rev = policy.RevisionIdx
		default:
			zerolog.Ctx(ctx).Warn().Str("Content-Type", cfg.ContentType).Msg("Unknown content type.")
		}
	}

	sub, err := o.pm.Subscribe(agent.Id, agent.PolicyID, rev)
	if err != nil {
		return nil, fmt.Errorf("unable to get policy subscription for agent: %w", err)
	}
	defer func() {
		err := o.pm.Unsubscribe(sub)
		if err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("Unable to unsubscribe from policy.")
		}
	}()
	var remoteConfig *protobufs.AgentRemoteConfig
	select {
	case pp := <-sub.Output():
		remoteConfig, _, err = o.preparePolicy(ctx, agent, pp)
		// FIXME: We should be sure to handle outputs separately here using the returned data (2nd arg)
		// At a minimum we need to set ConnectionSettingsOffers.opamp
		if err != nil {
			return nil, fmt.Errorf("unable to prepare remote config: %w", err)
		}
	default:
		zerolog.Ctx(ctx).Debug().Msg("No policy update.")
	}

	return &protobufs.ServerToAgent{
		InstanceUid:  message.InstanceUid,
		RemoteConfig: remoteConfig,
		Capabilities: serverCapabilities,
	}, nil
}

func (o *opamp) register(ctx context.Context, message *protobufs.AgentToServer, policyID string, namespaces []string) (*protobufs.ServerToAgent, error) {
	if message.GetCapabilities()&0x00000100 == 0 {
		return nil, fmt.Errorf("capability: AcceptsOpAMPConnectionSettings is unset")
	}
	// NOTE: message.ConnectionSettingsRequest.Opamp is used for a CSR flow, we don't support this workflow at the moment
	replaceID := message.GetFlags()&uint64(protobufs.AgentToServerFlags_AgentToServerFlags_RequestInstanceUid) != 0
	uid := ulid.ULID(message.InstanceUid)
	agent, err := dl.FindAgent(ctx, o.bulk, dl.QueryAgentByID, dl.FieldID, uid.String())
	if err == nil {
		// ID collides with an existing agent that has not checked in
		if agent.Id != "" && agent.LastCheckin == "" {
			if err := invalidateAPIKey(ctx, o.bulk, agent.AccessAPIKeyID); err != nil {
				return nil, fmt.Errorf("agent id collision, unable to invalidate previous API key: %w", err)
			}
			if err := o.bulk.Delete(ctx, dl.FleetAgents, agent.Id); err != nil {
				return nil, fmt.Errorf("agent id collision, unable to delete previous agent doc: %w", err)
			}
		} else {
			zerolog.Ctx(ctx).Debug().Msg("Agent registration has detected uid collision")
			uid = ulid.Make() // TODO replace this with a better call?
			replaceID = true
		}
	} else if errors.Is(err, dl.ErrNotFound) {
		zerolog.Ctx(ctx).Trace().Msg("Agent registration no uid collision")
	} else {
		return nil, fmt.Errorf("unable to check for uid collision on registration")
	}

	key, err := o.bulk.APIKeyCreate(ctx, uid.String(), "", []byte(kFleetAccessRolesJSON), apikey.NewMetadata(uid.String(), "", apikey.TypeAccess))
	if err != nil {
		return nil, fmt.Errorf("registration failed to make ApiKey: %w", err)
	}
	// TODO need a way to split agent description into local metadata, tags, and version info
	var localMeta json.RawMessage
	if ad := message.GetAgentDescription(); ad != nil {
		localMeta, err = json.Marshal(ad)
		if err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("Unable to marshal agent description")
		}
	}
	// TODO Invalidate key if func returns error after this
	agent = model.Agent{
		Active:         true,
		PolicyID:       policyID,
		Namespaces:     namespaces,
		Type:           "opamp", // regular agents use PERMANENT, might be nice to distinguish
		EnrolledAt:     time.Now().UTC().Format(time.RFC3339),
		LocalMetadata:  localMeta,
		AccessAPIKeyID: key.ID,
		ActionSeqNo:    []int64{sqn.UndefinedSeqNo},
		Agent: &model.AgentMetadata{
			ID: uid.String(),
			// TODO version
		},
		// TODO tags
		// TODO handle enrolmentId
	}
	body, err := json.Marshal(agent)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal agent doc: %w", err)
	}
	if _, err := o.bulk.Create(ctx, dl.FleetAgents, uid.String(), body, bulk.WithRefresh()); err != nil {
		return nil, fmt.Errorf("unable to index agent doc: %w", err)
	}
	// TODO: Set agent to inactive if error is returned below
	o.cache.SetAPIKey(*key, true)

	sub, err := o.pm.Subscribe(uid.String(), policyID, 0) // subscription should get the latest policy
	if err != nil {
		return nil, fmt.Errorf("failed to create policy subscription when registering agent: %w", err)
	}
	defer func() {
		err := o.pm.Unsubscribe(sub)
		if err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("Unable to unsubscribe from policy.")
		}
	}()

	var remoteConfig *protobufs.AgentRemoteConfig
	var data *model.PolicyData
	select {
	case pp := <-sub.Output():
		remoteConfig, data, err = o.preparePolicy(ctx, &agent, pp)
		if err != nil {
			return nil, fmt.Errorf("unable to prepare remote config: %w", err)
		}
	case <-time.After(time.Second * 5): // TODO make configurable
		return nil, fmt.Errorf("unable to retrieve policy within timeout")
	}
	// handle connection settings here
	// TODO the non-opamp settings
	hash := sha256.New()
	hash.Write([]byte(key.ID))
	hash.Write(data.Fleet)

	fleet := struct {
		Hosts []string `json:"hosts"`
	}{}
	if err := json.Unmarshal(data.Fleet, &fleet); err != nil {
		return nil, fmt.Errorf("unable to unmarshal fleet hosts: %w", err)
	}
	if len(fleet.Hosts) == 0 {
		return nil, fmt.Errorf("no fleet hosts found")
	}

	resp := &protobufs.ServerToAgent{
		InstanceUid:  message.InstanceUid,
		RemoteConfig: remoteConfig,
		Capabilities: serverCapabilities,
		ConnectionSettings: &protobufs.ConnectionSettingsOffers{
			Hash: hash.Sum(nil),
			Opamp: &protobufs.OpAMPConnectionSettings{
				DestinationEndpoint: fleet.Hosts[0] + DefaultPath,
				Headers: &protobufs.Headers{
					Headers: []*protobufs.Header{
						&protobufs.Header{
							Key:   "Authorization",
							Value: "ApiKey " + key.Token(),
						},
					},
				},
			},
		},
	}
	if replaceID {
		resp.AgentIdentification = &protobufs.AgentIdentification{
			NewInstanceUid: uid.Bytes(),
		}
	}

	return resp, nil
}

func (o *opamp) preparePolicy(ctx context.Context, agent *model.Agent, pp *policy.ParsedPolicy) (*protobufs.AgentRemoteConfig, *model.PolicyData, error) {
	zerolog.Ctx(ctx).Debug().Msg("Found policy update.")
	if len(pp.Policy.Data.Outputs) == 0 {
		return nil, nil, fmt.Errorf("no outputs defined in policy")
	}
	data := model.ClonePolicyData(pp.Policy.Data)
	for name, output := range data.Outputs {
		err := policy.ProcessOutputSecret(ctx, output, o.bulk)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to process output secrets %q: %w", name, err)
		}
	}
	for _, output := range pp.Outputs {
		err := output.Prepare(ctx, *zerolog.Ctx(ctx), o.bulk, agent, data.Outputs)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to pepare output %q: %w", output.Name, err)
		}
	}
	data.Inputs = pp.Inputs

	body, err := json.Marshal(data)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal policy: %w", err)
	}
	hash := sha256.New()
	hash.Write(body)
	remoteConfig := &protobufs.AgentRemoteConfig{
		Config: &protobufs.AgentConfigMap{
			ConfigMap: map[string]*protobufs.AgentConfigFile{
				"": &protobufs.AgentConfigFile{
					Body:        body,
					ContentType: "application/json",
				},
			},
		},
		ConfigHash: hash.Sum(nil),
	}
	return remoteConfig, data, nil
}

// toComponentsList will transform opamp components health to fleet's componets list
// it will only go one level down in the opamp map
func toComponentList(comps map[string]*protobufs.ComponentHealth) []model.ComponentsItems {
	if len(comps) == 0 {
		return nil
	}
	arr := make([]model.ComponentsItems, len(comps))
	for k, v := range comps {
		status := healthToStatus[v.Healthy]
		units := make([]model.UnitsItems, len(v.ComponentHealthMap))
		for uk, uv := range v.ComponentHealthMap {
			uStatus := healthToStatus[uv.Healthy]
			units = append(units, model.UnitsItems{
				ID:      uk,
				Message: uv.Status,
				Status:  uStatus,
			})
		}
		arr = append(arr, model.ComponentsItems{
			ID:      k,
			Message: v.Status,
			Status:  status,
			Units:   units,
		})
	}
	return arr
}

func invalidateAPIKey(ctx context.Context, bulker bulk.Bulk, id string) error {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
LOOP:
	for {
		_, err := bulker.APIKeyRead(ctx, id, true)
		switch {
		case err == nil:
			break LOOP
		case !errors.Is(err, apikey.ErrAPIKeyNotFound):
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("apikey index failed to refresh")
		case <-time.After(time.Second):
		}
	}
	return bulker.APIKeyInvalidate(ctx, id)
}
