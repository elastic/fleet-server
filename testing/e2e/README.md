# Fleet-server E2E Tests

Fleet-server E2E tests are black-box tests where a fleet-server binary is started and ran against the latest development released of Elasticsearch and Kibana.

The tests can be ran from the repo's root directory by running:
```bash
mage test:e2e
```

If you want to run specific tests, you can specify them via the `TEST_RUN` environment variable, as an expression that
is understood by the `go test -name` flag.
```bash
TEST_RUN='TestStandAloneRunningSuite/TestAPMInstrumentation' mage test:e2e
```

Please note that by default only the `StandAlone*` suites are executed.
The `Agent*` suites may not be up to date.

## Overview

E2E tests are written with [testify](https://pkg.go.dev/github.com/stretchr/testify) and [Testcontainers](https://pkg.go.dev/github.com/testcontainers/testcontainers-go).

The main touchpoints for adding a test are as follows:

- `stand_alone_test.go` - suite contains tests to ensure that the fleet-server is able to start with different configuration as a stand-alone binary.
- `stand_alone_container_test.go` - suite contains tests to ensure that the fleet-server is able to start with differnt configuration when running in a container.
- `stand_alone_api_test.go` - wrappers to lauch API client tests against a fleet-server running as a stand-alone binary
- `api_version/*` - suites and utilities to test the API endpoints with specific versions.

## API Tests

Fleet-server uses a versioned API.
Versioned API tests are done to ensure that fleet-server can respond correctly to clients running older versions.

Tests and utilities to access endpoints are defined as part of each version tester.

### Adding a new test

To add a new test to an API tester you just need to use [testify/suite](https://pkg.go.dev/github.com/stretchr/testify/suite) naming conventions.

That is, add a funtion to the version that starts with `Test`, for example

```go
// api_version/client_api_current.go
func (tester *ClientAPITester) TestSomething() {
    // write test code here
}

// api_version/client_api_2023_06_01.go
func (tester *ClientAPITester20230601) TestSomething() {
    // write test code here
}
```

The `TestSomething` methods will automatically be ran as part of the API test suites.

#### New endpoint example

An example of adding a test is adding a new endpoint to the API.
Here is how the `GET /api/agents/upgrades/:version/pgp-public-key` was added as a test.

First, make sure that the client implementation in `../pkg/api` has the new endpoint by running `mage generate` in the repo's root directory.

Next you should add a wrapper to the call in `api_version/client_api_current.go` that other test cases may use, this method should make and validate the call.
For example:

```go
func (tester *ClientAPITester) GetPGPKey(ctx context.Context, apiKey string) []byte {
	client, err := api.NewClientWithResponses(tester.endpoint, api.WithHTTPClient(tester.Client), api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
		return nil
	}))
	tester.Require().NoError(err)

	resp, err := client.GetPGPKeyWithResponse(ctx, 1, 2, 3)
	tester.Require().NoError(err)
	if strings.HasPrefix(tester.endpoint, "https") {
		tester.Require().Equal(http.StatusOK, resp.StatusCode())
	} else {
		tester.Require().Equal(http.StatusNotImplemented, resp.StatusCode())
	}
	return resp.Body
}
```

Other test cases may use `tester.GETPGPKey()` in order to retrieve the key from the endpoint if required

Next add the Test case that will be ran, for this endpoint we don't need any additional work to be done around setup or validation so our test is just a wrapper:

```go
func (tester *ClientAPITester) TestGetPGPKey() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tester.GetPGPKey(ctx, tester.enrollmentKey)
}
```

### Adding a new API version suite

Define a new client version and create the associated tester in `api_version`.
The tester should have and embedded `*scaffold.Scaffold` attribute in order to access elasticsearch/kibana utilities and a client that will function for the fleet-server (the `Scaffold` also embeds `suite.Suite` so `Test*` methods may be detected).
Make sure that the tester has a `SetEndpoint` and `SetKey` function that can be used to direct the testsuite at the target.

Add a suite struct and Test method for the tester in `stand_alone_api_test.go`, for example the `2023-06-01` looks like:

```go
type StandAlone20230601API struct {
	StandAloneAPIBase
	api_version.ClientAPITester20230601
}

func (suite *StandAlone20230601API) SetupSuite() {
	suite.StandAloneAPIBase.SetupSuite() // run the fleet-server gather the endpoint and enrollment token
	suite.SetEndpoint(suite.endpoint)    // set the tester endpoint
	suite.SetKey(suite.key)              // set the tester enrollmentKey
}

func TestStandAlone20230601API(t *testing.T) {
	s := new(StandAlone20230601API)
	s.ClientAPITester20230601.Scaffold = &s.StandAloneAPIBase.StandAloneBase.Scaffold // make sure the tester uses the same references as the suite that is getting executed

	suite.Run(t, s)
}
```
