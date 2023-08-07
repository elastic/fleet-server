package dl

import (
	"encoding/json"
	"net/http"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

type ExtendedClient struct {
	*elasticsearch.Client
	Custom *ExtendedAPI
}

type ExtendedAPI struct {
	*elasticsearch.Client
}

// GET /_fleet/secret/secretId
func (c *ExtendedAPI) Read(secretId string) (*esapi.Response, error) {
	req, err := http.NewRequest("GET", "/_fleet/secret/"+secretId, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if err != nil {
		return nil, err
	}

	res, err := c.Perform(req)
	if err != nil {
		return nil, err
	}
	return &esapi.Response{StatusCode: res.StatusCode, Body: res.Body, Header: res.Header}, nil
}

type SecretResponse struct {
	Id    string
	Value string
}

func ReadSecret(client *elasticsearch.Client, secretId string) (string, error) {
	es := ExtendedClient{Client: client, Custom: &ExtendedAPI{client}}
	res, err := es.Custom.Read(secretId)
	var secretResp SecretResponse

	defer res.Body.Close()

	err = json.NewDecoder(res.Body).Decode(&secretResp)
	if err != nil {
		return "", err
	}

	return secretResp.Value, err
}
