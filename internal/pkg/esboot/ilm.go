package esboot

import (
	"context"
	"encoding/json"
	"fleet/internal/pkg/esutil"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Can be cleaner but it's temporary bootstrap until it's moved to the elasticseach system index plugin

const (
	defaultILMPolicy = `
	{
		"policy":{
		   "phases":{
		   }
		}
	}`

	ilmRolloverSize = 300
	ilmRolloverAge  = 30
	ilmDeleteAge    = 90
	ilmPolicySuffix = "ilm-policy"
)

func EnsureILMPolicy(ctx context.Context, es *elasticsearch.Client, name string) error {
	policy := GetILMPolicyName(name)

	lg := log.With().Str("policy", policy).Logger()

	res, err := es.ILM.GetLifecycle(
		es.ILM.GetLifecycle.WithPolicy(policy),
		es.ILM.GetLifecycle.WithContext(ctx),
	)

	// Check if general error, network failure, timeout, etc.
	if err != nil {
		lg.Info().Err(err).Msgf("Failed to fetch ILM policy")
		return err
	}

	defer res.Body.Close()

	// Only create ILM lifecycle if we got a definite 404 from the server
	if res.StatusCode == http.StatusNotFound {
		// Got 404. Could be from elastic, could be from the cloud if deployment is not found.
		// Parse response to figure out the details from JSON body
		errRes, err := esutil.ParseResponseError(res)
		if err != nil {
			lg.Warn().Err(err).Msgf("Failed to parse ILM policy not found response.")
			return err
		}

		// Got 404 from Elasticsearch
		if errRes.Status == http.StatusNotFound {
			lg.Info().Msgf("ILM policy is not found. Create a new one.")
			err = createILMPolicy(ctx, es, name)
			if err != nil {
				return err
			}
			return nil
		}

		// Return elasticsearch error details
		return &esutil.ClientError{
			StatusCode: errRes.Status,
			Type:       errRes.Error.Type,
			Reason:     errRes.Error.Reason,
		}
	}

	// Check for other possible error responses
	err = esutil.CheckResponseError(res)
	if err != nil {
		lg.Info().Err(err).Msgf("Error response on fetching ILM Policy")
		return err
	}

	// No error found, ILM policy already exists
	lg.Info().Msg("Found ILM policy")

	// Fetched the ILM policy successfully. Check the settings and if they need to be updated.
	if res.StatusCode == http.StatusOK {
		err = checkUpdateILMPolicy(ctx, es, lg, policy, res.Body)
		if err != nil {
			lg.Warn().Err(err).Msg("Failed to update ILM policy settings")
			return err
		}
	}

	return nil
}

func checkUpdateILMPolicy(ctx context.Context, es *elasticsearch.Client, lg zerolog.Logger, name string, r io.Reader) error {
	policy := GetILMPolicyName(name)
	lg.Info().Msg("Check ILM policy settings if they need to be updated")

	var m stringMap
	err := json.NewDecoder(r).Decode(&m)
	if err != nil {
		return err
	}

	policyMap := m.GetMap(policy)

	phases := policyMap.GetMap("policy").GetMap("phases")
	rollover := phases.GetMap("hot").GetMap("actions").GetMap("rollover")

	existingRolloverSize := rollover.GetString("max_size")
	existingRolloverAge := rollover.GetString("max_age")
	existingDeleteAge := phases.GetMap("delete").GetString("min_age")

	newRolloverSize := renderSize(ilmRolloverSize)
	newRolloverAge := renderDays(ilmRolloverAge)
	newDeleteAge := renderDays(ilmDeleteAge)

	if existingRolloverSize != newRolloverSize ||
		existingRolloverAge != newRolloverAge ||
		existingDeleteAge != newDeleteAge {
		lg.Info().
			Str("old_rollover_size", existingRolloverSize).
			Str("new_rollover_size", newRolloverSize).
			Str("old_rollover_age", existingRolloverAge).
			Str("new_rollover_age", newRolloverAge).
			Str("old_delete_age", existingDeleteAge).
			Str("new_delete_age", newDeleteAge).
			Msgf("ILM policy settings were changed. Check if needs to be updated.")

		return createILMPolicy(ctx, es, name)
	}
	return nil
}

func createILMPolicy(ctx context.Context, es *elasticsearch.Client, name string) error {
	policy := GetILMPolicyName(name)
	body := mustRender(renderILMPolicy(ilmRolloverSize, ilmRolloverAge, ilmDeleteAge))

	// The elastic will respond with an error if the ILM policy doesn't exists
	// in that case let's just create the ILM policy
	log.Debug().Str("policy", policy).Str("body", body).Msg("Creating ILM policy")

	res, err := es.ILM.PutLifecycle(policy,
		es.ILM.PutLifecycle.WithBody(strings.NewReader(body)),
		es.ILM.PutLifecycle.WithContext(ctx),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return esutil.CheckResponseError(res)

	return nil
}

func GetILMPolicyName(name string) string {
	return nameWithSuffix(name, ilmPolicySuffix)
}

func nameWithSuffix(name, suffix string) string {
	return name + "-" + ilmPolicySuffix
}

func renderILMPolicy(rolloverSize, rolloverAge, deleteAge int) (s string, err error) {
	var m stringMap

	err = json.Unmarshal([]byte(defaultILMPolicy), &m)
	if err != nil {
		return s, err
	}

	phases := m.GetMap("policy").GetMap("phases")

	if rolloverAge != 0 || rolloverSize != 0 {
		hot := make(stringMap)
		rollover := make(stringMap)
		actions := make(stringMap)
		if rolloverSize != 0 {
			rollover["max_size"] = renderSize(rolloverSize)
		}
		if rolloverAge != 0 {
			rollover["max_age"] = renderDays(rolloverAge)
		}
		actions["rollover"] = rollover
		hot["actions"] = actions
		phases["hot"] = hot
	}

	if deleteAge != 0 {
		delete := make(stringMap)
		delete["min_age"] = renderDays(deleteAge)
		actions := make(stringMap)
		actions["delete"] = struct{}{}
		delete["actions"] = actions
		phases["delete"] = delete
	}

	b, err := json.Marshal(m)
	if err != nil {
		return s, err
	}

	return string(b), nil
}

func renderSize(size int) string {
	return strconv.Itoa(size) + "gb"
}

func renderDays(days int) string {
	return strconv.Itoa(days) + "d"
}

func mustRender(s string, err error) string {
	if err != nil {
		panic(err)
	}
	return s
}
