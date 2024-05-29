// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/reload"
	"github.com/elastic/fleet-server/v7/internal/pkg/sleep"
	"github.com/elastic/fleet-server/v7/internal/pkg/state"
	"github.com/elastic/fleet-server/v7/internal/pkg/ver"
	"github.com/rs/zerolog"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/go-ucfg"
	"gopkg.in/yaml.v3"
)

const (
	kAgentModeRestartLoopDelay = 2 * time.Second

	kFleetServer   = "fleet-server"
	kElasticsearch = "elasticsearch"

	kStopped = "Stopped"

	verifyNone = "none"
	// NOTE: Do we want to try to make this configurable in the future?
	// It may need different handling as we would want it to be part of the policy definition so a user
	// can specify in Kibana, but it only applies to agent mode.
	outputCheckLoopDelay = time.Minute
)

type clientUnit interface {
	Expected() client.Expected
	UpdateState(state client.UnitState, message string, payload map[string]interface{}) error
}

// Agent is a fleet-server that runs under the elastic-agent.
// An Agent instance will retrieve connection information from the passed reader (normally stdin).
// Agent uses client.StateInterface to gather config data and manage its lifecylce.
type Agent struct {
	cliCfg      *ucfg.Config
	bi          build.Info
	reloadables []reload.Reloadable

	agent client.V2

	outputUnit clientUnit
	inputUnit  clientUnit

	srv          *Fleet
	srvCtx       context.Context
	srvCanceller context.CancelFunc
	srvDone      chan bool

	outputCheckCanceller context.CancelFunc
	chReconfigure        chan struct{}
}

// NewAgent returns an Agent that will gather connection information from the passed reader.
func NewAgent(cliCfg *ucfg.Config, reader io.Reader, bi build.Info, reloadables ...reload.Reloadable) (*Agent, error) {
	var err error

	a := &Agent{
		cliCfg:        cliCfg,
		bi:            bi,
		reloadables:   reloadables,
		chReconfigure: make(chan struct{}, 1),
	}
	a.agent, _, err = client.NewV2FromReader(reader, client.VersionInfo{
		Name:      kFleetServer,
		BuildHash: bi.Commit,
		Meta: map[string]string{
			"commit":     bi.Commit,
			"build_time": bi.BuildTime.String(),
		},
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Run starts a Server instance using config from the configured client.
func (a *Agent) Run(ctx context.Context) error {
	log := zerolog.Ctx(ctx)
	a.agent.RegisterDiagnosticHook("fleet-server config", "fleet-server's current configuration", "fleet-server.yml", "application/yml", func() []byte {
		if a.srv == nil {
			log.Warn().Msg("Diagnostics hook failure fleet-server is nil.")
			return nil
		}
		cfg := a.srv.GetConfig()
		if cfg == nil {
			log.Warn().Msg("Diagnostics hook failure config is nil.")
			return nil
		}
		cfg = cfg.Redact()
		p, err := yaml.Marshal(cfg)
		if err != nil {
			log.Error().Err(err).Msg("Diagnostics hook failure config unable to marshal yaml.")
			return nil
		}
		return p
	})
	a.agent.RegisterDiagnosticHook("fleet-server api tls diag", "fleet-server's API TLS config", "fleet-server-api-tls.txt", "text/plain", func() []byte {
		if a.srv == nil {
			log.Warn().Msg("Diagnostics hook failure fleet-server is nil.")
			return nil
		}
		cfg := a.srv.GetConfig()
		if cfg == nil || len(cfg.Inputs) == 0 {
			log.Warn().Msg("Diagnostics hook failure config is nil.")
			return nil
		}
		return cfg.Inputs[0].Server.TLS.DiagCerts()()
	})
	a.agent.RegisterDiagnosticHook("fleet-server output tls diag", "fleet-server's output TLS config", "fleet-server-output-tls.txt", "text/plain", func() []byte {
		if a.srv == nil {
			log.Warn().Msg("Diagnostics hook failure fleet-server is nil.")
			return nil
		}
		cfg := a.srv.GetConfig()
		if cfg == nil {
			log.Warn().Msg("Diagnostics hook failure config is nil.")
			return nil
		}
		return cfg.Output.Elasticsearch.TLS.DiagCerts()()
	})
	a.agent.RegisterDiagnosticHook("fleet-server output request diag", "fleet-server output request trace diagnostics", "fleet-server-output-request.txt", "text/plain", func() []byte {
		if a.srv == nil {
			log.Warn().Msg("Diagnostics hook failure fleet-server is nil.")
			return nil
		}
		cfg := a.srv.GetConfig()
		if cfg == nil {
			log.Warn().Msg("Diagnostics hook failure config is nil.")
			return nil
		}
		return cfg.Output.Elasticsearch.DiagRequests(ctx)
	})

	subCtx, subCanceller := context.WithCancel(ctx)
	defer subCanceller()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		t := time.NewTicker(1 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-subCtx.Done():
				return
			case err := <-a.agent.Errors():
				if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
					log.Error().Err(err).Msg("Agent wrapper received error.")
				}
			case change := <-a.agent.UnitChanges():
				switch change.Type {
				case client.UnitChangedAdded:
					err := a.unitAdded(subCtx, change.Unit)
					if err != nil {
						log.Error().Str("unit", change.Unit.ID()).Err(err)
						_ = change.Unit.UpdateState(client.UnitStateFailed, err.Error(), nil)
					}
				case client.UnitChangedModified:
					err := a.unitModified(subCtx, change.Unit)
					if err != nil {
						log.Error().Str("unit", change.Unit.ID()).Err(err)
						_ = change.Unit.UpdateState(client.UnitStateFailed, err.Error(), nil)
					}
				case client.UnitChangedRemoved:
					a.unitRemoved(change.Unit)
				}
			case <-a.chReconfigure:
				err := a.reconfigure(ctx)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Error().Err(err).Msg("Error when reconfiguring from trigger")
				}
			case <-t.C:
				// Fleet Server is the only component that gets started by Elastic Agent without an Agent ID. We loop
				// here on interval waiting for the Elastic Agent to enroll so then the Agent ID is then set.
				agentInfo := a.agent.AgentInfo()
				if agentInfo != nil && agentInfo.ID != "" {
					// Agent ID is not set for the component.
					t.Stop()
					err := a.reconfigure(subCtx)
					if err != nil && !errors.Is(err, context.Canceled) {
						log.Error().Err(err).Msg("Bootstrap error when reconfiguring")
					}
				}
			}
		}
	}()

	log.Info().Msg("starting communication connection back to Elastic Agent")
	err := a.agent.Start(subCtx)
	if err != nil {
		return err
	}

	<-subCtx.Done()
	wg.Wait()

	return nil
}

// UpdateState updates the state of the message and payload.
func (a *Agent) UpdateState(state client.UnitState, message string, payload map[string]interface{}) error {
	if a.inputUnit != nil {
		_ = a.inputUnit.UpdateState(state, message, payload)
	}
	if a.outputUnit != nil {
		_ = a.outputUnit.UpdateState(state, message, payload)
	}
	return nil
}

func (a *Agent) unitAdded(ctx context.Context, unit *client.Unit) error {
	if unit.Type() == client.UnitTypeInput {
		exp := unit.Expected()
		if exp.Config.Type != kFleetServer {
			// not support input type
			_ = unit.UpdateState(client.UnitStateFailed, fmt.Sprintf("%s is an unsupported input type", exp.Config.Type), nil)
			return nil
		}
		if a.inputUnit != nil {
			// original input unit is being stopped; swapping in this unit as the new input unit
			_ = a.inputUnit.UpdateState(client.UnitStateStopped, kStopped, nil)
		}
		a.inputUnit = unit
		if a.outputUnit == nil {
			// waiting for output unit to really start Fleet Server
			_ = unit.UpdateState(client.UnitStateStarting, "waiting for output unit", nil)
			return nil
		}
		return a.start(ctx)
	}
	if unit.Type() == client.UnitTypeOutput {
		exp := unit.Expected()
		if exp.Config.Type != kElasticsearch {
			// not support output type
			_ = unit.UpdateState(client.UnitStateFailed, fmt.Sprintf("%s is an unsupported output type", exp.Config.Type), nil)
			return nil
		}
		if a.outputUnit != nil {
			// original output unit is being stopped; swapping in this unit as the new output unit
			_ = a.outputUnit.UpdateState(client.UnitStateStopped, kStopped, nil)
		}
		a.outputUnit = unit
		if a.inputUnit == nil {
			// waiting for input unit to really start Fleet Server
			_ = unit.UpdateState(client.UnitStateStarting, "waiting for input unit", nil)
			return nil
		}
		return a.start(ctx)
	}
	return fmt.Errorf("unknown unit type %v", unit.Type())
}

func (a *Agent) unitModified(ctx context.Context, unit *client.Unit) error {
	exp := unit.Expected()
	if unit.Type() == client.UnitTypeInput {
		if a.inputUnit != unit {
			// not our input unit; would have been marked failed in unitAdded; do nothing
			return nil
		}
		if exp.State == client.UnitStateHealthy {
			if a.outputUnit == nil {
				// still no output unit; would have been marked starting already; do nothing
				return nil
			}

			// configuration modified (should still be running)
			return a.reconfigure(ctx)
		} else if exp.State == client.UnitStateStopped {
			// unit should be stopped
			a.stop()
			return nil
		}
		return fmt.Errorf("unknown unit state %v", exp.State)
	}
	if unit.Type() == client.UnitTypeOutput {
		if a.outputUnit != unit {
			// not our output unit; would have been marked failed in unitAdded; do nothing
			return nil
		}
		if exp.State == client.UnitStateHealthy {
			if a.inputUnit == nil {
				// still no input unit; would have been marked starting already; do nothing
				return nil
			}

			// configuration modified (should still be running)
			return a.reconfigure(ctx)
		} else if exp.State == client.UnitStateStopped {
			// unit should be stopped
			a.stop()
			return nil
		}
		return fmt.Errorf("unknown unit state %v", exp.State)
	}
	return fmt.Errorf("unknown unit type %v", unit.Type())
}

func (a *Agent) unitRemoved(unit *client.Unit) {
	stop := false
	if a.inputUnit == unit || a.outputUnit == unit {
		stop = true
	}
	if stop {
		a.stop()
	}
	if a.inputUnit == unit {
		a.inputUnit = nil
	}
	if a.outputUnit == unit {
		a.outputUnit = nil
	}
}

func (a *Agent) start(ctx context.Context) error {
	if a.srv != nil {
		return a.reconfigure(ctx)
	}

	cfg, err := a.configFromUnits(ctx)
	if err != nil {
		return err
	}

	// reload the generic reloadables
	for _, r := range a.reloadables {
		err = r.Reload(ctx, cfg)
		if err != nil {
			return err
		}
	}

	srvDone := make(chan bool)
	srvCtx, srvCanceller := context.WithCancel(ctx)
	srv, err := NewFleet(a.bi, state.NewChained(state.NewLog(), a), false)
	if err != nil {
		close(srvDone)
		srvCanceller()
		return err
	}

	go func() {
		defer close(srvDone)
		for {
			err := srv.Run(srvCtx, cfg)
			if err == nil || errors.Is(err, context.Canceled) {
				return
			}
			// sleep some before calling Run again
			_ = sleep.WithContext(srvCtx, kAgentModeRestartLoopDelay)
		}
	}()

	a.srv = srv
	a.srvCtx = srvCtx
	a.srvCanceller = srvCanceller
	a.srvDone = srvDone
	return nil
}

func (a *Agent) reconfigure(ctx context.Context) error {
	if a.srv == nil {
		return a.start(ctx)
	}

	cfg, err := a.configFromUnits(ctx)
	if err != nil {
		return err
	}

	// reload the generic reloadables
	for _, r := range a.reloadables {
		err = r.Reload(ctx, cfg)
		if err != nil {
			return err
		}
	}

	return a.srv.Reload(ctx, cfg)
}

func (a *Agent) stop() {
	if a.srvCanceller == nil {
		return
	}
	if a.outputCheckCanceller != nil {
		a.outputCheckCanceller()
		a.outputCheckCanceller = nil
	}

	canceller := a.srvCanceller
	a.srvCanceller = nil
	a.srvCtx = nil
	a.srv = nil
	canceller()
	<-a.srvDone
	a.srvDone = nil

	if a.inputUnit != nil {
		_ = a.inputUnit.UpdateState(client.UnitStateStopped, kStopped, nil)
	}
	if a.outputUnit != nil {
		_ = a.outputUnit.UpdateState(client.UnitStateStopped, kStopped, nil)
	}
}

// configFromUnits takes both inputUnit and outputUnit and creates a single configuration just like fleet server was
// being started from a configuration file.
func (a *Agent) configFromUnits(ctx context.Context) (*config.Config, error) {
	agentID := ""
	agentVersion := ""
	agentInfo := a.agent.AgentInfo()
	if agentInfo != nil {
		agentID = agentInfo.ID
		agentVersion = agentInfo.Version
	}
	expInput := a.inputUnit.Expected()
	expOutput := a.outputUnit.Expected()
	logLevel := expInput.LogLevel
	if expOutput.LogLevel > logLevel {
		logLevel = expOutput.LogLevel
	}

	// pass inputs from policy through go-ucfg in order to flatten keys
	// if inputCfg.Source.AsMap() is passed directly, any additional server.* settings will be missed
	var input map[string]interface{}
	inputsConfig, err := ucfg.NewFrom(expInput.Config.Source.AsMap(), config.DefaultOptions...)
	if err != nil {
		return nil, err
	}
	if err := inputsConfig.Unpack(&input, config.DefaultOptions...); err != nil {
		return nil, err
	}
	outMap := expOutput.Config.Source.AsMap()

	// elastic-agent should be setting bootstrap with config provided through enrollment flags
	if bootstrapCfg, ok := outMap["bootstrap"]; ok {
		if a.outputCheckCanceller != nil {
			a.outputCheckCanceller()
			a.outputCheckCanceller = nil
		}

		bootstrap, ok := bootstrapCfg.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("output bootstrap attribute is not an object, detected type: %T", bootstrapCfg)
		}
		delete(outMap, "bootstrap")
		injectMissingOutputAttributes(ctx, outMap, bootstrap)

		if err := a.esOutputCheck(ctx, outMap); err != nil {
			if errors.Is(err, es.ErrElasticVersionConflict) || errors.Is(err, ver.ErrUnsupportedVersion) {
				zerolog.Ctx(ctx).Error().Err(err).Interface("output", outMap).Msg("Elasticsearch version constraint failed for new output")
			} else if errors.Is(err, context.Canceled) {
				// ignore logging cancelation errors in the output check
			} else {
				zerolog.Ctx(ctx).Warn().Err(err).Interface("output", outMap).Msg("Failed Elasticsearch output configuration test, using bootstrap values.")

				// try to reload periodically
				outputCtx, canceller := context.WithCancel(ctx)
				a.outputCheckCanceller = canceller
				go a.esOutputCheckLoop(outputCtx, outputCheckLoopDelay, outMap)
			}
			outMap = bootstrap // outMap fails to connect, revert to bootstrap
		}
	}

	cfgData, err := ucfg.NewFrom(map[string]interface{}{
		"fleet": map[string]interface{}{
			"agent": map[string]interface{}{
				"id":      agentID,
				"version": agentVersion,
			},
		},
		"output": map[string]interface{}{
			"elasticsearch": outMap,
		},
		"inputs": []interface{}{
			input,
		},
		"logging": map[string]interface{}{
			"level": logLevel.String(),
		},
	})
	if err != nil {
		return nil, err
	}

	if expAPMCFG := expInput.APMConfig; expAPMCFG != nil {
		instrumentationCfg, err := apmConfigToInstrumentation(expAPMCFG)
		if err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).Msg("Unable to parse expected APM config as instrumentation config")
		} else {
			obj := map[string]interface{}{
				"inputs": []interface{}{map[string]interface{}{
					"server": map[string]interface{}{
						"instrumentation": instrumentationCfg,
					},
				},
				}}
			err = cfgData.Merge(obj, config.MergeOptions...)
			if err != nil {
				zerolog.Ctx(ctx).Warn().Err(err).Msg("Failed to merge APM config into cfgData")
			}
		}

	}

	cliCfg := ucfg.MustNewFrom(a.cliCfg, config.DefaultOptions...)
	err = cliCfg.Merge(cfgData, config.DefaultOptions...)
	if err != nil {
		return nil, err
	}
	return config.FromConfig(cliCfg)
}

// apmConfigToInstrumentation transforms the passed APMConfig into the Instrumentation config that is used by fleet-server.
func apmConfigToInstrumentation(src *proto.APMConfig) (config.Instrumentation, error) {
	if apmest := src.GetElastic(); apmest != nil {
		apmTLS := apmest.GetTls()
		iTLS := config.InstrumentationTLS{
			SkipVerify:        apmTLS.GetSkipVerify(),
			ServerCertificate: apmTLS.GetServerCert(),
			ServerCA:          apmTLS.GetServerCa(),
		}

		cfg := config.Instrumentation{
			Enabled:      true,
			TLS:          iTLS,
			Environment:  apmest.GetEnvironment(),
			APIKey:       apmest.GetApiKey(),
			SecretToken:  apmest.GetSecretToken(),
			Hosts:        apmest.GetHosts(),
			GlobalLabels: apmest.GetGlobalLabels(),
		}
		return cfg, nil
	}
	return config.Instrumentation{}, fmt.Errorf("unable to transform APMConfig to instrumentation")
}

// injectMissingOutputAttributes will inject an explicit set of keys that may be present in bootstrap into outMap.
// If outmap has a certificate_authorities or a fingerprint, verification_mode: none will not be injected if it is part of bootstrap.
// Note that we avoiding a more generic injection here (iterating over all keys in bootstrap recursively) in order to avoid injecting any unnecessary/deprecated attributes.
func injectMissingOutputAttributes(ctx context.Context, outMap, bootstrap map[string]interface{}) {
	bootstrapKeys := []string{
		"protocol",
		"hosts",
		"path",
		"service_token",
		"service_token_path",
		"headers",
		"proxy_url",
		"proxy_disable",
		"proxy_headers",
	}
	// keys that will appear under the "ssl" key
	bootstrapSSLKeys := []string{
		"verification_mode",
		"certificate_authorities",
		"ca_trusted_fingerprint",
		"certificate",
		"key",
	}

	injectKeys(bootstrapKeys, outMap, bootstrap)

	// flags used to delete verification_mode: none if it is part of bootstrap and injected when output provides a CA of some sort.
	outputSSLUsesCA := false
	injectVerificationNone := false
	// handle nested structs in bootstrap, currently we just support some ssl config
	var bootstrapSSL map[string]interface{}
	if mp, ok := bootstrap["ssl"]; ok {
		bootstrapSSL, ok = mp.(map[string]interface{})
		if !ok {
			zerolog.Ctx(ctx).Warn().Interface("ssl_attribute", mp).Msg("Bootstrap ssl attribute is not an object.")
			// ssl is not a map
			// if bootstrap is used as output this will cause a parsing issue and fail later
			return
		}
		if v, ok := bootstrapSSL["verification_mode"]; ok {
			if s, ok := v.(string); ok && s == verifyNone {
				injectVerificationNone = true
			}
		}
	} else {
		// bootstrap has no ssl attributes
		return
	}

	outputSSL := map[string]interface{}{}
	if mp, ok := outMap["ssl"]; ok {
		outputSSL, ok = mp.(map[string]interface{})
		if !ok {
			zerolog.Ctx(ctx).Warn().Interface("ssl_attribute", mp).Msg("Policy ssl attribute is not an object.")
			// output.ssl is not a map
			// this will fail to parse later
			return
		}
		outputSSLUsesCA = checkForCA(outputSSL)
	}
	injectKeys(bootstrapSSLKeys, outputSSL, bootstrapSSL)
	if outputSSLUsesCA && injectVerificationNone {
		delete(outputSSL, "verification_mode")
	}

	outMap["ssl"] = outputSSL
}

// injectKeys will inject any key in the passed list that exists in src but is missing from dst.
func injectKeys(keys []string, dst, src map[string]interface{}) {
	for _, key := range keys {
		// dst contains the key
		if _, ok := dst[key]; ok {
			continue
		}
		// src does not contain the key
		if _, ok := src[key]; !ok {
			continue
		}
		dst[key] = src[key]
	}
}

// checkForCA checks to see if the passed cfg contains a certificate_authorities list with one item or a non-empty ca_trusted_fingerprint value.
func checkForCA(cfg map[string]interface{}) bool {
	// if the cfg contains verificaton_mode none return false
	if tmp, ok := cfg["verification_mode"]; ok {
		if verificationMode, ok := tmp.(string); ok && verificationMode == verifyNone {
			return false
		}
	}
	if tmp, ok := cfg["certificate_authorities"]; ok {
		if cas, ok := tmp.([]interface{}); ok && len(cas) > 0 {
			return true
		}
	}
	if tmp, ok := cfg["ca_trusted_fingerprint"]; ok {
		if fingerprint, ok := tmp.(string); ok && fingerprint != "" {
			return true
		}
	}
	return false
}

func (a *Agent) esOutputCheck(ctx context.Context, data map[string]interface{}) error {
	var esOut config.Elasticsearch
	temp, err := ucfg.NewFrom(data, config.DefaultOptions...)
	if err != nil {
		return err
	}
	if err := temp.Unpack(&esOut, config.DefaultOptions...); err != nil {
		return err
	}

	const httpsSchema = "https"
	isHTTPS := false
	for _, host := range esOut.Hosts {
		if strings.HasPrefix(strings.ToLower(host), httpsSchema) {
			isHTTPS = true
			break
		}
	}
	if isHTTPS {
		esOut.Protocol = httpsSchema
	}

	cli, err := es.NewClient(ctx,
		&config.Config{
			Output: config.Output{
				Elasticsearch: esOut,
			},
		},
		false,
		elasticsearchOptions(false, a.bi)..., // disable instrumentation for output config test
	)
	if err != nil {
		return err
	}
	_, err = ver.CheckCompatibility(ctx, cli, a.bi.Version)
	return err
}

// esOutputCheckLoop will periodically retest the passed (output) config and signal chReconfigure if it succeeds then return.
// If the context ic canceled, or an ErrElasticVersionConflict is returned (by the test) it will return
func (a *Agent) esOutputCheckLoop(ctx context.Context, delay time.Duration, cfg map[string]interface{}) {
	for {
		if err := sleep.WithContext(ctx, delay); err != nil {
			zerolog.Ctx(ctx).Debug().Msg("Async output check context cancelled")
			return
		}
		err := a.esOutputCheck(ctx, cfg)
		if err == nil {
			zerolog.Ctx(ctx).Debug().Msg("Async output check successful")
			a.chReconfigure <- struct{}{}
			return
		}
		if errors.Is(err, context.Canceled) {
			zerolog.Ctx(ctx).Debug().Msg("Async output check context cancelled")
			return
		}
		// connected to invalid ES version
		if errors.Is(err, es.ErrElasticVersionConflict) || errors.Is(err, ver.ErrUnsupportedVersion) {
			zerolog.Ctx(ctx).Error().Err(err).Interface("output", cfg).Msg("Elasticsearch version constraint failed for new output")
			return
		}
		zerolog.Ctx(ctx).Debug().Err(err).Interface("output", cfg).Msgf("Async output check failed, will retry after %v", delay)
	}
}
