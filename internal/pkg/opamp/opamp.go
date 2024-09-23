// opamp provides a poc of fleet-server serving the opamp spec
// It can serve new policies

package opamp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
)

const (
	healthy   = "healthy"
	unhealthy = "unhealthy"
)

const serverCapabilities uint64 = 0x00000001 | 0x00000002 | 0x00000004 // status, offers remote config, accepts effective config

type opamp struct {
	bulk  bulk.Bulk
	cache cache.Cache
}

func NewHandler(bulk bulk.Bulk, cache cache.Cache, pm policy.Monitor) *opamp {
	return &opamp{
		bulk:  bulk,
		cache: cache,
		pm:    pm,
	}
}

func (o *opamp) Process(ctx context.Context, agent *model.Agent, message *protobufs.AgentToServer) (*protobufs.ServerToAgent, error) {
	if agent.Id != string(message.InstanceUid) {
		return nil, fmt.Errorf("API key's associated agent does not match InstanceUid")
	}
	ts := time.Now().Unix()
	tsStr := ts.Format(time.RFC3339)

	// update the agent description if health status has changed. otherwise just a minimal update
	updateAgent := false
	if health := message.GetHealth(); health != nil &&
		(health.Healthy && agent.LastCheckinStatus != healty) ||
		(!health.Healthy && agent.LastCheckinStatus != unhealthy) {
		updateAgent = true
	}
	update := bulk.UpdateFields{
		dl.FieldLastCheckin: tsStr,
		dl.FieldUpdatedAt:   tsStr,
	}
	if updateAgent {
		if message.GetHealth().Healthy {
			update[dl.FieldLastCheckinStatus] = healthy
		} else {
			update[dl.FieldLastCheckinStatus] = unhealthy
		}
		update[dl.FieldLastCheckinMessage] = message.GetHealth().Status
		// TODO: map ComponentHealthMap to components list
	}
	updateBody, err := fields.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal agent update: %w", err)
	}
	if err := o.bulk.Update(ctx, dl.FleetAgents, agent.Agent.ID, updateBody); err != nil {
		return nil, fmt.Errorf("failed to update agent doc: %w", err)
	}

	rev := agent.PolicyRevisionIdx
	// use revisionIDx from agent's config if it's sent
	var cfg protobuf.AgentConfigFile
	ecfg := message.GetEffectiveConfig()
	if ecfg != nil {
		if cm := ecfg.GetConfigMap(); cm != nil {
			if cfile, ok := cm[""]; ok {
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
			rev = policy.RebisionIdx
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
			zerolog.Ctx(ctx).Error().Err(err).Msg("Unable to subscribe from policy.")
		}
	}()
	var remoteConfig *protobuf.AgentRemoteConfig
	select {
	case pp := sub.Output():
		zerolog.Ctx(ctx).Debug().Msg("Found policy update.")
		if len(pp.Policy.Data.Outputs) == 0 {
			return nil, fmt.Errorf("no outputs defined in policy")
		}
		data := model.ClonePolicyData(pp.Policy.Data)
		for name, output := range data.Outputs {
			err := policy.ProcessOutputSecret(ctx, output, o.bulk)
			if err != nil {
				return nil, fmt.Errorf("failed to process output secrets %q: %w", name, err)
			}
		}
		for _, output := range pp.Outputs {
			err := output.Prepare(ctx, zerolog.Ctx(ctx), o.bulk, agent, data.Outputs)
			if err != nil {
				return nil, fmt.Errorf("failed to pepare output %q: %w", output.Name, err)
			}
		}
		data.Inputs = pp.Inputs
		body, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal policy: %w", err)
		}
		remoteConfig = &protobuf.AgentRemoteConfig{
			Body:        p,
			ContentType: "application/json",
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
