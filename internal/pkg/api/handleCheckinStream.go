// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package api

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-json-experiment/json/jsontext"

	"github.com/miolini/datacounter"
	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/checkin"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

// componentFlushThreshold is the number of component bytes accumulated before
// issuing a partial ES update while still reading the request body.
const componentFlushThreshold int64 = 4 * 1024 * 1024

// streamParseCheckinRequest decodes a CheckinRequest from r using jsontext streaming.
// It is specifically meant to stream the components array into a sequence of intermediate ES updates
// so the the fleet-server does not have to decode a large request into memory at once (in order to avoid OOM issues).
// it return a CheckinRequest without Components, and the unhealthyReason parsed from the components (if any)
func (ct *CheckinT) streamParseCheckinRequest(r io.Reader, threshold int64, agent *model.Agent) (CheckinRequest, *[]string, error) {
	dec := jsontext.NewDecoder(r)
	var req CheckinRequest
	var reason *[]string

	tok, err := dec.ReadToken()
	if err != nil {
		return req, reason, fmt.Errorf("opening token: %w", err)
	}
	if tok.Kind() != jsontext.KindBeginObject {
		return req, reason, fmt.Errorf("expected JSON object, got %s", tok.Kind().String())
	}

	for dec.PeekKind() != jsontext.KindEndObject {
		keyTok, err := dec.ReadToken()
		if err != nil {
			return req, reason, fmt.Errorf("json read key: %w", err)
		}
		key := keyTok.String()

		switch key {
		case "components":
			unhealthyReason, err := ct.streamComponentsArray(dec, threshold, agent)
			if err != nil {
				return req, reason, fmt.Errorf("json error streaming components: %w", err)
			}
			reason = unhealthyReason
		default:
			val, err := dec.ReadValue()
			if err != nil {
				return req, reason, fmt.Errorf("json read error %q: %w", key, err)
			}
			if err := assignCheckinRequestField(&req, key, val); err != nil {
				return req, reason, fmt.Errorf("struct assign error %q: %w", key, err)
			}
		}
	}

	if _, err := dec.ReadToken(); err != nil {
		return req, reason, fmt.Errorf("failed to read closing token: %w", err)
	}
	return req, reason, nil
}

// streamComponentsArray reads the components JSON array from dec.
// It flushes partial arrays as intermediate updates to ES.
// Returns the unhealthy reason collected from the components
func (ct *CheckinT) streamComponentsArray(dec *jsontext.Decoder, threshold int64, agent *model.Agent) (*[]string, error) {
	if dec.PeekKind() == jsontext.KindNull {
		// FIXME need to clean component list in ES if we ever get here
		// If this ever happens it means that the content length was either set to -1
		// or some other part of the request is greater than the checkin body limit
		// there is no guard against the latter from occurring
		if _, err := dec.ReadToken(); err != nil { // consume null
			return nil, err
		}
		return nil, nil
	}

	arrTok, err := dec.ReadToken()
	if err != nil {
		return nil, err
	}
	if arrTok.Kind() != jsontext.KindBeginArray {
		return nil, fmt.Errorf("expected array, got %c", arrTok.Kind())
	}

	var (
		components  = make([]model.ComponentsItems, 0, 100) // 100 is arbitrary to pre allocate some space
		reason      []string
		flushNum    int
		accumulated int64
	)

	for dec.PeekKind() != jsontext.KindEndArray {
		val, err := dec.ReadValue()
		if err != nil {
			return nil, fmt.Errorf("read component element: %w", err)
		}
		accumulated += int64(len(val))

		var component model.ComponentsItems
		if err := json.Unmarshal(val, &component); err != nil {
			return nil, fmt.Errorf("parse component element: %w", err)
		}

		components = append(components, component)

		if accumulated >= threshold {
			reason = append(reason, calcUnhealthyReason(components)...)
			if err := ct.bc.CheckIn(agent.Id, checkin.WithComponentsStream(components, flushNum)); err != nil {
				return nil, fmt.Errorf("partial component update failed: %w", err)
			}
			flushNum++
			clear(components)           // zero elements
			components = components[:0] // set len to 0 without removing capacity
			accumulated = 0
		}
	}

	// Consume closing ]
	if _, err := dec.ReadToken(); err != nil {
		return nil, err
	}

	if flushNum == 0 && len(components) == 0 {
		// FIXME update ES with no components here too
		return nil, nil
	}
	if len(components) > 0 {
		reason = append(reason, calcUnhealthyReason(components)...)
		if err := ct.bc.CheckIn(agent.Id, checkin.WithComponentsStream(components, flushNum)); err != nil {
			return nil, fmt.Errorf("partial component update failed: %w", err)
		}
	}
	return &reason, nil
}

// assignCheckinRequestField unmarshals val into the named field of req.
// Unknown fields are silently ignored, matching standard JSON decoder behaviour.
func assignCheckinRequestField(req *CheckinRequest, key string, val jsontext.Value) error {
	switch key {
	case "ack_token":
		var v string
		if err := json.Unmarshal(val, &v); err != nil {
			return err
		}
		req.AckToken = &v
	case "agent_policy_id":
		var v string
		if err := json.Unmarshal(val, &v); err != nil {
			return err
		}
		req.AgentPolicyId = &v
	case "local_metadata":
		req.LocalMetadata = json.RawMessage(val.Clone())
	case "message":
		return json.Unmarshal(val, &req.Message)
	case "policy_revision_idx":
		return json.Unmarshal(val, &req.PolicyRevisionIdx)
	case "poll_timeout":
		var v string
		if err := json.Unmarshal(val, &v); err != nil {
			return err
		}
		req.PollTimeout = &v
	case kStatusMod:
		return json.Unmarshal(val, &req.Status)
	case "upgrade":
		req.Upgrade = json.RawMessage(val.Clone())
	case "upgrade_details":
		req.UpgradeDetails = new(UpgradeDetails)
		return json.Unmarshal(val, req.UpgradeDetails)
	}
	return nil
}

// validateRequestStream is the streaming request validator.
// It uses jsontext to parse the request body token-by-token, specifically to handle
// the components array seperatly from other attributes.
// When validating the request stream, ES will receive intermediate updates to the components
// array before things like status are set.
// The return validatdCheckin object will have the Components attribute set to nil.
//
// FIXME: go v1.27+ this is a PoC to demonstrate stream-read behaviour only
func (ct *CheckinT) validateRequestStream(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, start time.Time, agent *model.Agent) (validatedCheckin, error) {
	span, ctx := apm.StartSpan(r.Context(), "validateRequestStream", "validate")
	defer span.End()

	readCounter := datacounter.NewReaderCounter(r.Body)

	var bodyReader io.Reader = readCounter
	if r.Header.Get("Content-Encoding") == kEncodingGzip {
		gr, err := gzip.NewReader(readCounter)
		if err != nil {
			return validatedCheckin{}, &BadRequestErr{msg: "unable to create gzip reader for request body", nextErr: err}
		}
		defer gr.Close()
		bodyReader = gr
	}

	req, unhealthyReason, err := ct.streamParseCheckinRequest(bodyReader, componentFlushThreshold, agent)
	if err != nil {
		return validatedCheckin{}, &BadRequestErr{msg: "unable to decode checkin request", nextErr: err}
	}
	cntCheckin.bodyIn.Add(readCounter.Count())

	if unhealthyReason == nil {
		// fallback to agent doc if no reason found
		unhealthyReason = &agent.UnhealthyReason
		if agent.UnhealthyReason == nil && (agent.LastCheckinStatus == FailedStatus || agent.LastCheckinStatus == DegradedStatus) {
			// set to other if no reason found, and agent is not healthy
			unhealthyReason = &([]string{"other"})
		}
	}

	if req.Status == CheckinRequestStatus("") {
		return validatedCheckin{}, &BadRequestErr{msg: "checkin status missing"}
	}
	if len(req.Message) == 0 {
		zlog.Warn().Msg("checkin request method is empty.")
	}

	var pDur time.Duration
	if req.PollTimeout != nil {
		pDur, err = time.ParseDuration(*req.PollTimeout)
		if err != nil {
			return validatedCheckin{}, &BadRequestErr{msg: "poll_timeout cannot be parsed as duration", nextErr: err}
		}
	}

	pollDuration := ct.cfg.Timeouts.CheckinLongPoll
	if pDur != 0 {
		pollDuration = max(min(pDur-(2*time.Minute), ct.cfg.Timeouts.CheckinMaxPoll), time.Minute)
		wTime := pollDuration + time.Minute
		rc := http.NewResponseController(w)
		if err := rc.SetWriteDeadline(start.Add(wTime)); err != nil {
			zlog.Warn().Err(err).Time("write_deadline", start.Add(wTime)).Msg("Unable to set checkin write deadline.")
		} else {
			zlog.Trace().Time("write_deadline", start.Add(wTime)).Msg("Request write deadline set.")
		}
	}
	zlog.Trace().Dur("pollDuration", pollDuration).Msg("Request poll duration set.")

	rawMeta, err := parseMeta(zlog, agent, &req)
	if err != nil {
		return validatedCheckin{}, &BadRequestErr{msg: "unable to parse meta", nextErr: err}
	}

	seqno, err := ct.resolveSeqNo(ctx, zlog, req, agent)
	if err != nil {
		return validatedCheckin{}, err
	}

	rawRollbacks, err := parseAvailableRollbacks(zlog, agent.Upgrade, &req)
	if err != nil {
		zlog.Warn().Err(err).Msg("unable to parse available rollbacks")
		rawRollbacks = nil
	}

	return validatedCheckin{
		req:                   &req,
		dur:                   pollDuration,
		rawMeta:               rawMeta,
		seqno:                 seqno,
		unhealthyReason:       unhealthyReason,
		rawAvailableRollbacks: rawRollbacks,
	}, nil
}
