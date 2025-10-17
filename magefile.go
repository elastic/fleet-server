// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build mage

package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/fleet-server/v7/version"
)

var Default = Build.Binary

var Aliases = map[string]interface{}{
	"build":   Build.Binary,
	"release": Build.Release,
	"check":   Check.All,
	"test":    Test.All,
}

// env vars that a user can use to control targets.
const (
	// envSnapshot is the bool env var to indicate if it's a snapshot build.
	envSnapshot = "SNAPSHOT"
	// envDev is the bool env var to indicate if it's a dev build.
	envDev = "DEV"
	// envFips is the bool env var to indicate if it's a fips-capable build.
	envFIPS = "FIPS"
	// envPlatorms is a string env var, it should be specified as comma seperated list.
	envPlatforms = "PLATFORMS"
	// envVersionQualifier is a string env var that represents the version pre-release quantifier.
	envVersionQualifier = "VERSION_QUALIFIER"
	// envBenchmarkFilter is a string env var that is used to filter what benchmarks run. Defaults to "Bench".
	envBenchmarkFilter = "BENCHMARK_FILTER"
	//envBenchmarkArgs is a string env var that is used to pass benchmark specific args.
	envBenchmarkArgs = "BENCHMARK_ARGS"
	// envBenchBase is used to indicate the base input arg when running benchstat, or the ourput file for a benchmark command. Defaults to build/benchmark-$COMMIT.out.
	envBenchBase = "BENCH_BASE"
	// envBenchNext is used to indicate the comparison input arg when running benchstat. Empty by default
	envBenchNext = "BENCH_NEXT"
	// envDockerImage is used to indicate the base image name when tagging/pushing dockder images.
	envDockerImage = "DOCKER_IMAGE"
	// envDockerTag is used to indicate tag for images produced by the docker:image target. Defaults to version. It
	envDockerTag = "DOCKER_IMAGE_TAG"
	// envDockerBaseImage is the base image for elastic-agent-cloud images used by e2e tests.
	envDockerBaseImage = "DOCKER_BASE_IMAGE"
	// envDockerBaseImageTag is the tag for the base image used by e2e tests.
	envDockerBaseImageTag = "DOCKER_BASE_IMAGE_TAG"
)

// const and vars used by magefile.
const (
	binaryName = "fleet-server"
	binaryExe  = "fleet-server.exe"

	dockerSuffix      = "main-debian11"
	dockerArmSuffix   = "base-arm-debian11"
	dockerBuilderFile = "Dockerfile.build"
	dockerBuilderFIPS = "Dockerfile.fips"
	dockerBuilderName = "fleet-server-builder"
	dockerImage       = "docker.elastic.co/beats-ci/elastic-agent-cloud-fleet"
	dockerAgentImage  = "fleet-server-e2e-agent"
	dockerFleetImage  = "docker.elastic.co/observability-ci/fleet-server"
)

// e2e test certs
var (
	certDir   = filepath.Join("build", "e2e-certs")
	caFile    = filepath.Join(certDir, "e2e-test-ca.crt")
	caKeyFile = filepath.Join(certDir, "e2e-test-ca.key")
	certFile  = filepath.Join(certDir, "fleet-server.crt")
	keyFile   = filepath.Join(certDir, "fleet-server.key")
	passFile  = filepath.Join(certDir, "passphrase")
)

var (
	// platforms is the list of all supported platforms.
	platforms = []string{
		"darwin/amd64",
		"darwin/arm64",
		"linux/amd64",
		"linux/arm64",
		"windows/amd64",
	}
	// plaformsFIPS is the list of all FIPS-capable platforms.
	platformsFIPS = []string{
		"linux/amd64",
		"linux/arm64",
	}

	// platformsDocker is the list of all platforms that are supported by docker multiplatform builds.
	platformsDocker = []string{
		"linux/amd64",
		"linux/arm64",
	}

	// platformRemap contains mappings for platforms where if the GOOS/GOARCH key is used, artifacts should use the value instead. Missing keys are unalted.
	platformRemap = map[string]string{
		"darwin/amd64":  "darwin/x86_64",
		"darwin/arm64":  "darwin/aarch64",
		"linux/amd64":   "linux/x86_64",
		"windows/amd64": "windows/x86_64",
	}
)

// apmRole is used in the e2e tests to create an API key the apm-server can use.
const apmRole = `{
  "name": "apm-server-key",
  "role_descriptors": {
    "apm_writer": {
      "cluster": ["monitor"],
      "index": [
        {
          "names": ["traces-apm*","logs-apm*", "metrics-apm*"],
          "privileges": ["auto_configure", "create_doc"]
        }
      ]
    },
    "apm_sourcemap": {
      "index": [
        {
          "names": [".apm-source-map"],
          "privileges": ["read"]
        }
      ]
    },
    "apm_agentcfg": {
      "index": [
        {
          "names": [".apm-agent-configuration"],
          "privileges": ["read"],
          "allow_restricted_indices": true
        }
      ]
    },
    "apm_tail_based_sampling": {
        "index": [
            {
                "names": ["traces-apm.sampled"],
                "privileges": ["read"]
            }
        ]
    }
  }
}`

// collection of functions that return values that should not change when mage is executed.
var (
	// getVersion always returns the same version complete with qualifiers.
	getVersion = sync.OnceValue(func() string {
		var ver string = version.DefaultVersion
		if qualifier, ok := os.LookupEnv(envVersionQualifier); ok && qualifier != "" {
			ver += "-" + qualifier
		}
		if isSnapshot() { // NOTE: We can have both the qualifier and SNAPSHOT which is not allowed by semver
			ver += "-SNAPSHOT"
		}
		return ver
	})

	// getCommitID always returns the same commit ID.
	getCommitID = sync.OnceValue(func() string {
		id, err := sh.Output("git", "rev-parse", "--short", "HEAD")
		if err != nil {
			log.Printf("Cannot retrieve hash: %v", err)
			return ""
		}
		return id
	})

	// getBuildTime always returns the same time.
	getBuildTime = sync.OnceValue(func() string {
		return time.Now().UTC().Format(time.RFC3339)
	})

	// getGoVersion always returns the version from the .go-version file.
	// The runtime.Version is used if there is an error reading the file.
	getGoVersion = sync.OnceValue(func() string {
		p, err := os.ReadFile(".go-version")
		if err != nil {
			v := strings.TrimPrefix(runtime.Version(), "go")
			log.Printf("Unable to read .go-version: %v, using version from runtime: %s.", err, v)
			return v
		}
		return strings.TrimSpace(string(p))
	})

	// getLinterVersion parses the workflow/golangci-lint.yml file once and returns the linter version.
	getLinterVersion = sync.OnceValue(func() string {
		p, err := os.ReadFile(filepath.Join(".github", "workflows", "golangci-lint.yml"))
		if err != nil {
			log.Printf("Unable to read golangci-lint.yml: %v", err)
			return ""
		}
		obj := struct {
			Jobs struct {
				Golangci struct {
					Steps []struct {
						Name string `yaml:"name"`
						With struct {
							Version string `yaml:"version"`
						} `yaml:"with"`
					} `yaml:"steps"`
				} `yaml:"golangci"`
			} `yaml:"jobs"`
		}{}
		if err := yaml.Unmarshal(p, &obj); err != nil {
			log.Printf("Unmarshal golangci-lint.yml failure: %v", err)
			return ""
		}
		for _, step := range obj.Jobs.Golangci.Steps {
			if step.Name == "golangci-lint" {
				return step.With.Version
			}
		}
		log.Println("Unable to find golangci-lint version.")
		return ""
	})

	// getPlatforms returns a list of supported platforms.
	//
	// If a user specifies platforms through the env var, getPlatforms will filter out unsupported values.
	// If as a result of this filtering no valid platforms are detected, the default list will be used.
	getPlatforms = sync.OnceValue(func() []string {
		list := platforms
		if isFIPS() {
			list = platformsFIPS
		}
		// If env var is used ensure values are supported.
		if pList, ok := os.LookupEnv(envPlatforms); ok {
			filtered := make([]string, 0)
			for _, plat := range strings.Split(pList, ",") {
				if slices.Contains(list, plat) {
					filtered = append(filtered, plat)
				} else {
					log.Printf("Skipping %q platform is not in the list of allowed platforms.", plat)
				}
			}
			if len(filtered) > 0 {
				return filtered
			}
			log.Printf("%s env var detected but value %q does not contain valid platforms. Using default list.", envPlatforms, pList)
		}
		return list
	})

	// getDockerPlatforms returns a list of supported docker multiplatform targets.
	getDockerPlatforms = sync.OnceValue(func() []string {
		list := platformsDocker
		if pList, ok := os.LookupEnv(envPlatforms); ok {
			filtered := make([]string, 0)
			for _, plat := range strings.Split(pList, ",") {
				if slices.Contains(list, plat) {
					filtered = append(filtered, plat)
				} else {
					log.Printf("Skipping %q platform is not in the list of allowed platforms.", plat)
				}
			}
			if len(filtered) > 0 {
				return filtered
			}
			log.Printf("%s env var detected but value %q does not contain valid platforms. Using default list.", envPlatforms, pList)
		}
		return list
	})

	// isFIPS returns a bool indicator of the FIPS env var.
	isFIPS = sync.OnceValue(func() bool {
		return envToBool(envFIPS)
	})

	// isDEV returns a bool indicator of the DEV env var.
	isDEV = sync.OnceValue(func() bool {
		return envToBool(envDev)
	})

	// isSnapshot returns a bool indicator of the SNAPSHOT env var.
	isSnapshot = sync.OnceValue(func() bool {
		return envToBool(envSnapshot)
	})

	// getTagsString returns a comma seperated list of go build tags.
	getTagsString = sync.OnceValue(func() string {
		tags := []string{"grpcnotrace"}
		if isSnapshot() {
			tags = append(tags, "snapshot")
		}
		if isFIPS() {
			tags = append(tags, "requirefips")
		}
		return strings.Join(tags, ",")
	})

	// getGCFlags returns a string that can be used as the gcflags arg.
	getGCFlags = sync.OnceValue(func() string {
		if isDEV() {
			return "all=-N -l"
		}
		return ""
	})

	// getLDFlags returns a string that can be used as the ldflags arg.
	getLDFlags = sync.OnceValue(func() string {
		flags := fmt.Sprintf("-X main.Version=%s -X main.Commit=%s -X main.BuildTime=%s", getVersion(), getCommitID(), getBuildTime())
		if !isDEV() {
			return "-s -w " + flags
		}
		return flags
	})
)

// Check is the namespace for code checks.
type Check mg.Namespace

// Build is the namespace associated with building binaries.
type Build mg.Namespace

// Test is the namespace for running tests.
type Test mg.Namespace

// Docker is the namespace for docker related tasks.
type Docker mg.Namespace

// envToBool reads the env var string s and parses it as a bool.
func envToBool(s string) bool {
	v, ok := os.LookupEnv(s)
	if !ok {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

// environMap returns a map of all os.Environ values.
// this is not done in a sync.OnceValue as other methods, such as addFIPSEnvVars may alter the map.
func environMap() map[string]string {
	env := make(map[string]string)
	for _, s := range os.Environ() {
		k, v, _ := strings.Cut(s, "=")
		env[k] = v
	}
	return env
}

// addFIPSEnvVars mutates the passed env map by adding settings needed to produce a FIPS-capable binary.
func addFIPSEnvVars(env map[string]string) {
	env["GOEXPERIMENT"] = "systemcrypto"
	env["CGO_ENABLED"] = "1"
	env["MS_GOTOOLCHAIN_TELEMETRY_ENABLED"] = "0"
}

// teeCommand runs the specified command, stdout and stederr will be written to stdout and will be collected and returned.
func teeCommand(env map[string]string, cmd string, args ...string) ([]byte, error) {
	var b bytes.Buffer
	w := io.MultiWriter(&b, os.Stdout)
	_, err := sh.Exec(env, w, w, cmd, args...)
	return b.Bytes(), err
}

// ---- TARGETS BELOW ----

// GetVersion displays the fleet-server version with all qualifiers.
func GetVersion() {
	fmt.Println(getVersion())
}

// Platforms displays all possible plaforms.
func Platforms() {
	fmt.Println(strings.Join(getPlatforms(), " "))
}

// Multipass launches a mulitpass instance for development.
// FIPS may be used  to provision microsoft/go in the VM.
func Multipass() error {
	params := map[string]string{
		"Arch":        runtime.GOARCH,
		"DownloadURL": fmt.Sprintf("https://go.dev/dl/go%s.linux-%s.tar.gz", getGoVersion(), runtime.GOARCH),
	}
	if isFIPS() {
		params["DownloadURL"] = fmt.Sprintf("https://aka.ms/golang/release/latest/go%s.linux-%s.tar.gz", getGoVersion(), runtime.GOARCH)
	}

	// write the multipass-cloud-init.yml to launch the instance
	outF, err := os.CreateTemp("", "multipass-cloud-init-*.yml")
	if err != nil {
		return fmt.Errorf("unable to create multipass-cloud-init-*.yml file: %w", err)
	}
	fName := outF.Name()
	defer os.Remove(fName)
	defer outF.Close()

	t, err := template.ParseFiles(filepath.Join("dev-tools", "multipass-cloud-init.tpl"))
	if err != nil {
		return fmt.Errorf("unable to parse %s: %w", filepath.Join("dev-tools", "multipass-cloud-init.tpl"), err)
	}
	err = t.Execute(outF, params)
	if err != nil {
		return fmt.Errorf("unable to execute cloud init template: %w", err)
	}
	if err := outF.Sync(); err != nil {
		return fmt.Errorf("unable to sync cloud init template to disk: %w", err)
	}

	// launch the instance
	return sh.RunV("multipass", "launch", "--cloud-init="+fName, "--mount", "..:~/git", "--name", "fleet-server-dev", "--memory", "8G", "--cpus", "2", "--disk", "50G", "noble")
}

// Clean removes build artifacts.
func Clean() error {
	var err error
	for _, s := range []string{"bin", "build", ".service_token_kibana", ".service_token_fleet-server", ".service_token_fleet-server-remote", ".apm_server_api_key"} {
		log.Println("Removing:", s)
		if e := os.RemoveAll(s); e != nil {
			err = errors.Join(err, fmt.Errorf("error removing %q: %w", s, e))
		}
	}
	return err
}

// Generate creates and formats go code from schema models.
func Generate() error {
	out, err := sh.Output("go", "generate", "./...")
	if err != nil {
		fmt.Println(out)
		return fmt.Errorf("go generate failure: %w", err)
	}
	mg.Deps(Check.Headers)
	return nil
}

// ---- LINTER TARGETS BELOW ----

// Headers ensures files have copyright headers.
func (Check) Headers() error {
	return sh.Run("go", "tool", "-modfile", filepath.Join("dev-tools", "go.mod"), "github.com/elastic/go-licenser", "-license", "Elastic")
}

// Notice generates the NOTICE.txt and NOTICE-fips.txt files.
func (Check) Notice() {
	mg.SerialDeps(mg.F(genNotice, false), mg.F(genNotice, true))
}

// DetectFIPSCryptoImports will do a best effort attempt to ensure that the imports list for FIPS compatible artifacts does not contain any external crypto libraries.
// Specifically it will fail if the modules list contains an entry with: "crypto", "gokrb5", or "pbkdf2"
func (Check) DetectFIPSCryptoImports() error {
	tags := []string{"requirefips"}
	mods, err := getModules(tags...)
	if err != nil {
		return err
	}

	args := append([]string{"list", "-m"}, mods...)
	output, err := sh.Output("go", args...)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(output, "\n") {
		// keywords are crypto for x/crypto imports, gokrb5 for kerberos, and pbkdf2 for pbkdf2 generation
		for _, keyword := range []string{"crypto", "gokrb5", "pbkdf2"} {
			if strings.Contains(line, keyword) {
				err = errors.Join(err, fmt.Errorf("Detected import %s may implement crypto functionality", line))
			}
		}
	}
	return err
}

// genNotice generates the NOTICE.txt or the NOTICE-fips.txt file.
func genNotice(fips bool) error {
	tags := []string{}
	outFile := "NOTICE.txt"
	if fips {
		log.Println("Generating NOTICE-fips.txt.")
		tags = append(tags, "requirefips")
		outFile = "NOTICE-fips.txt"
	} else {
		log.Println("Generating NOTICE.txt.")
	}

	// Clean up modfile and download all needed files before building NOTICE
	err := sh.Run("go", "mod", "tidy")
	if err != nil {
		return fmt.Errorf("go mod tidy failure: %w", err)
	}
	err = sh.Run("go", "mod", "download")
	if err != nil {
		return fmt.Errorf("go mod download failure: %w", err)
	}

	mods, err := getModules(tags...)
	if err != nil {
		return fmt.Errorf("gathering go mods failure: %w", err)
	}
	slices.Sort(mods)

	listArgs := []string{"list", "-m", "-json"}
	listArgs = append(listArgs, mods...)
	listCmd := exec.Command("go", listArgs...)

	detectorCmd := exec.Command("go", "tool", "-modfile", filepath.Join("dev-tools", "go.mod"), "go.elastic.co/go-licence-detector",
		"-includeIndirect",
		"-rules", filepath.Join("dev-tools", "notice", "rules.json"),
		"-overrides", filepath.Join("dev-tools", "notice", "overrides.json"),
		"-noticeTemplate", filepath.Join("dev-tools", "notice", "NOTICE.txt.tmpl"),
		"-noticeOut", outFile,
		"-depsOut", "",
	)

	var buf bytes.Buffer
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()

	// Pipe output of go list command into licence-detector.
	listCmd.Stdout = w
	detectorCmd.Stdin = r
	detectorCmd.Stderr = &buf

	if err := listCmd.Start(); err != nil {
		return fmt.Errorf("error starting go list: %w", err)
	}
	if err := detectorCmd.Start(); err != nil {
		return fmt.Errorf("error starting go-licence-detector: %w", err)
	}
	if err := listCmd.Wait(); err != nil {
		return fmt.Errorf("go list failure: %w", err)
	}
	w.Close()

	if err := detectorCmd.Wait(); err != nil {
		log.Printf("go-licence-dector error: %v stderr: %s", err, buf.String())
		return fmt.Errorf("go-licence-detector failure: %w", err)
	}

	// Run go mod tidy as a cleanup
	return sh.Run("go", "mod", "tidy")
}

// getModules returns a list of direct and indirect modules that are used by the main package and its dependencies.
// Test and tooling packages are excluded.
func getModules(extraTags ...string) ([]string, error) {
	tags := append([]string{"linux", "darwin", "windows"}, extraTags...)
	args := []string{
		"list",
		"-deps",
		"-f",
		"{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}",
		"-tags",
		strings.Join(tags, ","),
	}
	output, err := sh.Output("go", args...)
	if err != nil {
		return nil, fmt.Errorf("go list failure: %w", err)
	}
	modsMap := map[string]struct{}{}
	for _, line := range strings.Split(output, "\n") {
		if len(line) > 0 {
			modsMap[string(line)] = struct{}{}
		}
	}
	return slices.Collect(maps.Keys(modsMap)), nil
}

// NoChanges ensures that there are no local changes to the codebase.
func (Check) NoChanges() error {
	if err := sh.Run("go", "mod", "tidy", "-v"); err != nil {
		return fmt.Errorf("go mod tidy failure: %w", err)
	}
	// sh.Output instead of sh.RunV as RunV has some level of terminal control that makes buildkite hang.
	out, err := sh.Output("git", "diff")
	if len(out) > 0 {
		fmt.Println(out)
	}
	if err != nil {
		return fmt.Errorf("git diff failure: %w", err)
	}
	if out, err := sh.Output("git", "update-index", "--refresh"); err != nil {
		fmt.Println(out)
		return fmt.Errorf("git update-index failure: %w", err)
	}
	if out, err := sh.Output("git", "diff-index", "--exit-code", "HEAD", "--"); err != nil {
		fmt.Println(out)
		return fmt.Errorf("git diff-index failure: %w", err)
	}
	return nil
}

// Imports runs goimports to reorder imports.
func (Check) Imports() error {
	return sh.Run("go", "tool", "-modfile", filepath.Join("dev-tools", "go.mod"), "golang.org/x/tools/cmd/goimports", "-w", ".")
}

// Ci runs CI related checks - runs generate, imports, checkHeaders, notice, checkNoChanges.
func (Check) Ci() {
	mg.SerialDeps(Generate, Check.Imports, Check.Headers, Check.Notice, Check.NoChanges)
}

// Go installs and runs golangci-lint.
// FIPS enables linting for files containing the requirefips tag.
func (Check) Go() error {
	mg.Deps(getLinter)
	if isFIPS() {
		return sh.RunV("golangci-lint", "run", "-v", "--build-tags", "requirefips")
	}
	return sh.RunV("golangci-lint", "run", "-v")
}

// getLinter ensures that the linter of the correct version is installed to GOPATH.
func getLinter() error {
	// exit early if linter exists with same version.
	if output, err := sh.Output("golangci-lint", "version", "--short"); err == nil && output == strings.TrimPrefix(getLinterVersion(), "v") {
		log.Println("Linter installation detected.")
		return nil
	}
	log.Printf("Linter version %q not detected, installing linter.", getLinterVersion())

	resp, err := http.Get("https://raw.githubusercontent.com/golangci/golangci-lint/d58dbde584c801091e74a00940e11ff18c6c68bd/install.sh")
	if err != nil {
		return fmt.Errorf("http request error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected 200 status, got %d", resp.StatusCode)
	}

	pathOut, err := sh.Output("go", "env", "GOPATH")
	if err != nil {
		return fmt.Errorf("go env failure: %w", err)
	}

	cmd := exec.Command("sh", "-s", "--", "-b", filepath.Join(strings.TrimSpace(pathOut), "bin"), getLinterVersion())
	cmd.Stdin = resp.Body
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Unable to install golangci-lint err: %v output: %s", err, string(out))
		return fmt.Errorf("golangci-lint installation failure: %w", err)
	}
	log.Printf("Linter version %s has been installed to %s.", getLinterVersion(), filepath.Join(strings.TrimSpace(pathOut), "bin"))
	return nil
}

// All runs all code checks: check:ci, check:go.
// FIPS passes the requirefips tag to the linter.
func (Check) All() {
	mg.SerialDeps(Check.Ci, Check.Go)
}

// ---- BUILD TARGETS BELOW ----

// Local builds a binary for the local environment.
// DEV creates a development build.
// SNAPSHOT creates a snapshot build.
// FIPS creates a FIPS capable binary.
func (Build) Local() error {
	env := environMap()
	env["CGO_ENABLED"] = "0"
	if isFIPS() {
		addFIPSEnvVars(env)
	}
	outFile := filepath.Join("bin", binaryName)
	if runtime.GOOS == "windows" {
		outFile = filepath.Join("bin", binaryExe)

	}
	return sh.RunWithV(env, "go", "build", "-tags="+getTagsString(), "-gcflags="+getGCFlags(), "-ldflags="+getLDFlags(), "-o", outFile, ".")
}

// Binary builds release binaries for the specified platforms.
// PLATFORMS may be used to set os/arch for compiled binaries.
// DEV creates a development build.
// SNAPSHOT creates a snapshot build.
// FIPS creates a FIPS capable binary.
// VERSION_QUALIFIER may be used to manually specify a version qualifer for the produced binary.
func (Build) Binary() {
	mg.Deps(mg.F(mkDir, filepath.Join("build", "binaries")))
	deps := make([]interface{}, 0)
	for _, platform := range getPlatforms() {
		osArg, archArg, _ := strings.Cut(platform, "/")
		deps = append(deps, mg.F(goBuild, osArg, archArg, false))
	}
	mg.SerialDeps(deps...)
}

// goBuild runs go build for the passed osArg/archArg.
// If cover is true the binary will be build with coverage enabled.
func goBuild(osArg, archArg string, cover bool) error {
	env := environMap()
	env["GOOS"] = osArg
	env["GOARCH"] = archArg
	env["CGO_ENABLED"] = "0"
	distArr := []string{"fleet-server"}
	if isFIPS() {
		addFIPSEnvVars(env)
		distArr = append(distArr, "fips")
	}
	binary := binaryName
	if osArg == "windows" {
		binary = binaryExe
	}
	osName := osArg
	archName := archArg
	if v, ok := platformRemap[osArg+"/"+archArg]; ok {
		osName, archName, _ = strings.Cut(v, "/")
	}
	distArr = append(distArr, getVersion(), osName, archName)
	outFile := filepath.Join("build", "binaries", strings.Join(distArr, "-"), binary)
	if cover {
		outFile = filepath.Join("build", "cover", strings.Join(distArr, "-"), binary)
	}

	args := []string{
		"build",
		"-tags=" + getTagsString(),
		"-gcflags=" + getGCFlags(),
		"-ldflags=" + getLDFlags(),
		"-o", outFile,
	}
	if cover {
		args = append(args, "-cover", "-coverpkg=./...")
	}
	args = append(args, ".")

	return sh.RunWithV(env, "go", args...)
}

// Cover builds coverage enabled binaries for all specified platforms.
// PLATFORMS may be used to set os/arch for compiled binaries.
// DEV creates a development build.
// SNAPSHOT creates a snapshot build.
// FIPS creates a FIPS capable binary.
// VERSION_QUALIFIER may be used to manually specify a version qualifer for the produced binary.
func (Build) Cover() {
	mg.Deps(mg.F(mkDir, filepath.Join("build", "cover")))
	deps := make([]interface{}, 0)
	for _, platform := range getPlatforms() {
		osArg, archArg, _ := strings.Cut(platform, "/")
		deps = append(deps, mg.F(goBuild, osArg, archArg, true))
	}
	mg.SerialDeps(deps...)
}

// Release builds and packages release artifacts for the specified platforms.
// PLATFORMS may be used to set os/arch for artifacts.
// DEV creates a development artifact.
// SNAPSHOT creates a snapshot artifact.
// FIPS creates a FIPS capable artifact.
// VERSION_QUALIFIER may be used to manually specify a version qualifer for the produced artifact.
func (Build) Release() {
	mg.Deps(Build.Binary, mg.F(mkDir, filepath.Join("build", "distributions")))
	deps := make([]interface{}, 0)
	for _, platform := range getPlatforms() {
		osName, archName, _ := strings.Cut(platform, "/")
		if v, ok := platformRemap[platform]; ok {
			osName, archName, _ = strings.Cut(v, "/")
		}
		if osName == "windows" { // windows distributions are zip not tar.gz
			deps = append(deps, mg.F(packageWindows, archName))
			continue
		}
		deps = append(deps, mg.F(packageNix, osName, archName))
	}
	mg.SerialDeps(deps...)
}

// mkDir is an internal function to be used as a dependency when a directory is needed.
func mkDir(dir string) error {
	return os.MkdirAll(dir, 0o755)
}

// packageWindows creates a Windows zip distribution for the specified architecture and provides the sha512 sum of the zip.
func packageWindows(arch string) error {
	distArr := []string{"fleet-server"}
	if isFIPS() {
		distArr = append(distArr, "fips")
	}
	distArr = append(distArr, getVersion(), "windows", arch)
	distName := strings.Join(distArr, "-")
	srcFile, err := os.Open(filepath.Join("build", "binaries", distName, binaryExe))
	if err != nil {
		return fmt.Errorf("unable to open src file: %w", err)
	}
	defer srcFile.Close()
	outFile, err := os.Create(filepath.Join("build", "distributions", distName+".zip"))
	if err != nil {
		return fmt.Errorf("unable to create zip file: %w", err)
	}
	defer outFile.Close()
	fileName := outFile.Name()

	zw := zip.NewWriter(outFile)
	defer zw.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("unable to stat src file: %w", err)
	}

	// Create the parent dir
	dirStat, err := os.Stat(filepath.Join("build", "binaries", distName))
	if err != nil {
		return fmt.Errorf("unable to stat dir: %w", err)
	}
	dirHeader, err := zip.FileInfoHeader(dirStat)
	if err != nil {
		return fmt.Errorf("unable to turn dir stat into header: %w", err)
	}
	if !strings.HasSuffix(dirHeader.Name, "/") {
		dirHeader.Name += "/"
	}
	_, err = zw.CreateHeader(dirHeader)
	if err != nil {
		return fmt.Errorf("unable to create zip dir: %w", err)
	}

	// Write the fleet-server.exe file into the archive
	header, err := zip.FileInfoHeader(srcInfo)
	if err != nil {
		return fmt.Errorf("unable to turn srcInfo into header: %w", err)
	}
	header.Name = filepath.ToSlash(filepath.Join(distName, binaryExe))
	zf, err := zw.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("unable to create fleet-server.exe header in zip: %w", err)
	}
	if _, err := io.Copy(zf, srcFile); err != nil {
		return fmt.Errorf("error copying fleet-server.exe into zip: %w", err)
	}

	zw.Close()
	outFile.Close()

	return genSha512(fileName)
}

// genSha512 computes the SHA-512 for the passed filename and saves the result to a file name fileName.sha512.
func genSha512(fileName string) error {
	f, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("unable to open %s: %w", fileName, err)
	}
	sum := sha512.New()
	if _, err := io.Copy(sum, f); err != nil {
		return fmt.Errorf("unable to read %s: %w", fileName, err)
	}
	computedHash := hex.EncodeToString(sum.Sum(nil))
	output := fmt.Sprintf("%v  %v", computedHash, filepath.Base(fileName))
	return os.WriteFile(fileName+".sha512", []byte(output), 0o644)
}

// packgeNix creates a .tar.gz archive for the specified os/arch and provides a sha512 sum for the distribution.
func packageNix(osArg, archArg string) error {
	distArr := []string{"fleet-server"}
	if isFIPS() {
		distArr = append(distArr, "fips")
	}
	distArr = append(distArr, getVersion(), osArg, archArg)
	distName := strings.Join(distArr, "-")
	srcFile, err := os.Open(filepath.Join("build", "binaries", distName, binaryName))
	if err != nil {
		return fmt.Errorf("unable to open src file: %w", err)
	}
	outFile, err := os.Create(filepath.Join("build", "distributions", distName+".tar.gz"))
	if err != nil {
		return fmt.Errorf("unable to create tar.gz file: %w", err)
	}
	defer outFile.Close()
	zw := gzip.NewWriter(outFile)
	tw := tar.NewWriter(zw)
	defer zw.Close()
	defer tw.Close()
	fileName := outFile.Name()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("unable to stat src file: %w", err)
	}

	// Write the fleet-server file into the archive - seperate parent dir is not needed.
	header, err := tar.FileInfoHeader(srcInfo, srcInfo.Name())
	if err != nil {
		return fmt.Errorf("unable to turn srcInfo to header: %w", err)
	}
	header.Name = filepath.ToSlash(filepath.Join(distName, binaryName))
	err = tw.WriteHeader(header)
	if err != nil {
		return fmt.Errorf("unable to create fleet-server tar.gz header: %w", err)
	}
	if _, err := io.Copy(tw, srcFile); err != nil {
		return fmt.Errorf("unable to copy fleet-server into tar.gz: %w", err)
	}

	tw.Close()
	zw.Close()
	outFile.Close()

	return genSha512(fileName)
}

// ---- DOCKER TARGETS BELOW ----

// Builder creates a docker image used to cross-compile binaries.
// This image is only built locally and should not be pushed to remote registries.
// Image produced is tagged as: fleet-server-builder:$GO_VERSION
// FIPS is used to create ina image that has the microsoft/go tool available so FIPS binaries may be compiled.
func (Docker) Builder() error {
	suffix := dockerSuffix
	if runtime.GOARCH == "arm64" {
		suffix = dockerArmSuffix
	}

	args := []string{"build", "-t", dockerBuilderName + ":" + getGoVersion(), "--build-arg", "GO_VERSION=" + getGoVersion()}
	if isFIPS() {
		args = append(args, "-f", dockerBuilderFIPS, "--build-arg", "SUFFIX="+suffix+"-fips", "--target", "base", ".")
	} else {
		args = append(args, "-f", dockerBuilderFile, "--build-arg", "SUFFIX="+suffix, ".")
	}
	return sh.RunV("docker", args...)
}

// Release builds releases within a docker image produced by docker:builder.
// PLATFORMS may be used to set os/arch for artifacts.
// DEV creates a development artifact.
// SNAPSHOT creates a snapshot artifact.
// FIPS creates a FIPS capable artifact.
// VERSION_QUALIFIER may be used to manually specify a version qualifer for the produced artifact.
func (Docker) Release() error {
	mg.Deps(mg.F(mkDir, filepath.Join("build", ".magefile")), Docker.Builder)
	return dockerRun("build:release")
}

// dockerRun runs the target on a container produced by docker:builder.
func dockerRun(target string) error {
	userInfo, err := user.Current()
	if err != nil {
		return fmt.Errorf("unable to lookup current user: %w", err)
	}
	pwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("unable to get wd: %w", err)
	}
	return sh.RunV("docker", "run", "--rm",
		"-u", userInfo.Uid+":"+userInfo.Gid,
		"--env=GOCACHE=/go/cache",
		"--volume", pwd+":/fleet-server/",
		"-e", envPlatforms+"="+strings.Join(getPlatforms(), ","),
		"-e", envDev+"="+strconv.FormatBool(isDEV()),
		"-e", envFIPS+"="+strconv.FormatBool(isFIPS()),
		"-e", envSnapshot+"="+strconv.FormatBool(isSnapshot()),
		"-e", envVersionQualifier+"="+os.Getenv(envVersionQualifier),
		dockerBuilderName+":"+getGoVersion(), target,
	)
}

// Binary builds binaries within a docker image produced by docker:builder.
// PLATFORMS may be used to set os/arch for compiled binaries.
// DEV creates a development build.
// SNAPSHOT creates a snapshot build.
// FIPS creates a FIPS capable binary.
// VERSION_QUALIFIER may be used to manually specify a version qualifer for the produced binary.
func (Docker) Binary() error {
	mg.Deps(mg.F(mkDir, filepath.Join("build", ".magefile")), Docker.Builder)
	return dockerRun("build:binary")
}

// Cover builds coverage enabled binaries within a docker image produced by docker:builder.
// PLATFORMS may be used to set os/arch for compiled binaries.
// DEV creates a development build.
// SNAPSHOT creates a snapshot build.
// FIPS creates a FIPS capable binary.
// VERSION_QUALIFIER may be used to manually specify a version qualifer for the produced binary.
func (Docker) Cover() error {
	mg.Deps(mg.F(mkDir, filepath.Join("build", ".magefile")), Docker.Builder)
	return dockerRun("build:cover")
}

// Image creates a stand-alone fleet-server image.
// The name of the image is docker.elastic.co/beats-ci/elastic-agent-cloud-fleet by default.
// FIPS creates a FIPS capable image, adds the -fips suffix to the image name.
// DEV creates a development image.
// SNAPSHOT creates a snapshot image.
// VERSION_QUALIFIER may be used to manually specify a version qualifer for the image tag.
// DOCKER_IMAGE may be used to completely specify the image name.
// DOCKER_IMAGE_TAG may be used to completely specify the image tag.
func (Docker) Image() error {
	dockerFile := "Dockerfile"
	image := dockerImage
	version := getVersion()
	if v, ok := os.LookupEnv(envDockerTag); ok && v != "" {
		version = v
	} else if isDEV() {
		version += "-dev"
	}
	suffix := dockerSuffix
	if runtime.GOARCH == "arm64" {
		suffix = dockerArmSuffix
	}
	if isFIPS() {
		dockerFile = dockerBuilderFIPS
		image += "-fips"
		suffix += "-fips"
	}
	if v, ok := os.LookupEnv(envDockerImage); ok && v != "" {
		image = v
	}

	return sh.RunWithV(map[string]string{"DOCKER_BUILDKIT": "1"}, "docker", "build",
		"--build-arg", "GO_VERSION="+getGoVersion(),
		"--build-arg", "DEV="+strconv.FormatBool(isDEV()),
		"--build-arg", "FIPS="+strconv.FormatBool(isFIPS()),
		"--build-arg", "SNAPSHOT="+strconv.FormatBool(isSnapshot()),
		"--build-arg", "VERSION="+getVersion(),
		"--build-arg", "GCFLAGS="+getGCFlags(),
		"--build-arg", "LDFLAGS="+getLDFlags(),
		"--build-arg", "SUFFIX="+suffix,
		"-f", dockerFile,
		"-t", image+":"+version,
		".",
	)
}

// Publish creates a multiplatform images and pushes them to the registry.
// The name of the image is docker.elastic.co/observability-ci/fleet-server by default.
// FIPS creates a FIPS capable image, adds the -fips suffix to the image name.
// DEV creates a development image.
// SNAPSHOT creates a snapshot image.
// VERSION_QUALIFIER may be used to manually specify a version qualifer for the image tag.
// DOCKER_IMAGE may be used to completely specify the image name.
// DOCKER_IMAGE_TAG may be used to completely specify the image tag.
// PLATFORMS may be used to specify multiplatform build targets. Defaults to [linux/amd64, linux/arm64].
func (Docker) Publish() error {
	dockerFile := "Dockerfile"
	image := dockerFleetImage
	version := getVersion()
	if v, ok := os.LookupEnv(envDockerTag); ok && v != "" {
		version = v
	}
	suffix := dockerSuffix
	if runtime.GOARCH == "arm64" {
		suffix = dockerArmSuffix
	}
	if isFIPS() {
		dockerFile = dockerBuilderFIPS
		image += "-fips"
		suffix += "-fips"
	}
	if v, ok := os.LookupEnv(envDockerImage); ok && v != "" {
		image = v
	}
	if v, ok := os.LookupEnv(envDockerImage); ok && v != "" {
		image = v
	}
	dockerEnv := map[string]string{"DOCKER_BUILDKIT": "1"}
	if err := sh.RunWithV(dockerEnv, "docker", "buildx", "create", "--use"); err != nil {
		return fmt.Errorf("docker buildx create failed: %w", err)
	}

	return sh.RunWithV(dockerEnv, "docker", "buildx", "build", "--push",
		"--platform", strings.Join(getDockerPlatforms(), ","),
		"--build-arg", "GO_VERSION="+getGoVersion(),
		"--build-arg", "DEV="+strconv.FormatBool(isDEV()),
		"--build-arg", "FIPS="+strconv.FormatBool(isFIPS()),
		"--build-arg", "SNAPSHOT="+strconv.FormatBool(isSnapshot()),
		"--build-arg", "VERSION="+getVersion(),
		"--build-arg", "GCFLAGS="+getGCFlags(),
		"--build-arg", "LDFLAGS="+getLDFlags(),
		"--build-arg", "SUFFIX="+suffix,
		"-f", dockerFile,
		"-t", image+":"+version,
		".",
	)
}

// Push pushs an image created by docker:image to the registry.
// FIPS may be used to push a FIPS capable image.
// DOCKER_IMAGE may be used to specify the image name.
// DOCKER_IMAGE_TAG may be used to specify the image tag.
func (Docker) Push() error {
	image := dockerImage
	if isFIPS() {
		image += "-fips"
	}
	if v, ok := os.LookupEnv(envDockerImage); ok && v != "" {
		image = v
	}

	version := getVersion()
	if v, ok := os.LookupEnv(envDockerTag); ok && v != "" {
		version = v
	}

	return sh.RunV("docker", "push", image+":"+version)
}

// CustomAgentImage creates a custom elastic-agent image where the fleet-server component has been replaced by one built locally.
// This step requires a coverage enabled binary to be used.
// FIPS is used to control if a FIPS compliant image should be created.
// DOCKER_BASE_IMAGE may be used to specify the elastic-agent base image. docker.elastic.co/cloud-release/elastic-agent-cloud by default.
// DOCKER_BASE_IMAGE_TAG may be used to specify the elastic-agent base image tag. Uses the ELASTICESRCH version from dev-tools/integration/.env.
// DOCKER_IMAGE is used to specify the resulting image name.
// DOCKER_IMAGE_TAG is used to specify the resulting image tag.
func (Docker) CustomAgentImage() error {
	env, err := readEnvFile(filepath.Join("dev-tools", "integration", ".env"))
	if err != nil {
		return fmt.Errorf("unable to read env file: %w", err)
	}

	baseImage := "docker.elastic.co/cloud-release/elastic-agent-cloud"
	if v, ok := os.LookupEnv(envDockerBaseImage); ok && v != "" {
		baseImage = v
	}
	baseImageTag := env["ELASTICSEARCH_VERSION"]
	if v, ok := os.LookupEnv(envDockerBaseImageTag); ok && v != "" {
		baseImageTag = v
	}

	dockerEnv := map[string]string{"DOCKER_BUILDKIT": "1"}
	err = sh.RunWithV(dockerEnv, "docker", "pull", "--platform", "linux/"+runtime.GOARCH, baseImage+":"+baseImageTag)
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}
	vcsRef, err := sh.OutputWith(dockerEnv, "docker", "inspect", "-f", "{{index .Config.Labels \"org.label-schema.vcs-ref\" }}", baseImage+":"+baseImageTag)
	if err != nil {
		return fmt.Errorf("unable to find vcs-ref label: %w", err)
	}
	dockerImage := dockerAgentImage
	if v, ok := os.LookupEnv(envDockerImage); ok && v != "" {
		dockerImage = v
	}
	tag := fmt.Sprintf("git-%s-%d", getCommitID(), time.Now().Unix())
	if v, ok := os.LookupEnv(envDockerTag); ok && v != "" {
		tag = v
	}
	fips := ""
	if isFIPS() {
		fips = "-fips"
	}
	err = sh.RunWithV(dockerEnv, "docker", "build",
		"-f", filepath.Join("dev-tools", "e2e", "Dockerfile"),
		"--build-arg", "ELASTIC_AGENT_IMAGE="+baseImage+":"+baseImageTag,
		"--build-arg", "STACK_VERSION="+getVersion(),
		"--build-arg", "VCS_REF_SHORT="+vcsRef[:6],
		"--build-arg", "FLEET_FIPS="+fips,
		"--platform", "linux/"+runtime.GOARCH,
		"-t", dockerImage+":"+tag,
		"build", // build is specified instead of . (and having build/cover/... in the Dockerfile) as build is part of the .dockerignore and this avoids checksum missing issues.
	)
	if err != nil {
		return fmt.Errorf("failed to build custom agent image: %w", err)
	}
	if err := os.WriteFile(filepath.Join("build", "custom-image"), []byte(dockerImage+":"+tag), 0o644); err != nil {
		log.Printf("Unable to save reference to custom agent image: %v", err)
	}
	log.Printf("Custom docker image: %s:%s", dockerImage, tag)

	return nil
}

// ---- TEST TARGETS BELOW ----

// Unit runs unit tests.
// Produces a unit test output file, and test coverage file in the build directory.
// SNAPSHOT adds the snapshot build tag.
// FIPS adds the requirefips build tag.
func (Test) Unit() error {
	mg.Deps(mg.F(mkDir, "build"))
	output, err := teeCommand(environMap(), "go", "test", "-tags="+getTagsString(), "-v", "-race", "-coverprofile="+filepath.Join("build", "coverage-"+runtime.GOOS+".out"), "./...")
	err = errors.Join(err, os.WriteFile(filepath.Join("build", "test-unit-"+runtime.GOOS+".out"), output, 0o644))
	return err
}

// UnitFIPSOnly runs unit tests and injects GODEBUG=fips140=only into the environment.
// This is done because mage may have issues when running with fips140=only set.
// Produces a unit test output file, and test coverage file in the build directory.
// SNAPSHOT adds the snapshot build tag.
// FIPS adds the requirefips build tag.
func (Test) UnitFIPSOnly() error {
	mg.Deps(mg.F(mkDir, "build"))

	// We also set GODEBUG=tlsmlkem=0 to disable the X25519MLKEM768 TLS key
	// exchange mechanism; without this setting and with the GODEBUG=fips140=only
	// setting, we get errors in tests like so:
	// Failed to connect: crypto/ecdh: use of X25519 is not allowed in FIPS 140-only mode
	// Note that we are only disabling this TLS key exchange mechanism in tests!
	env := environMap()
	env["GODEBUG"] = "fips140=only,tlsmlkem=0"

	output, err := teeCommand(env, "go", "test", "-tags="+getTagsString(), "-v", "-race", "-coverprofile="+filepath.Join("build", "coverage-"+runtime.GOOS+".out"), "./...")
	err = errors.Join(err, os.WriteFile(filepath.Join("build", "test-unit-fipsonly-"+runtime.GOOS+".out"), output, 0o644))
	return err
}

// Integration provisions the integration test environment with docker compose, runs the integration tests, then destroys the environment.
// SNAPSHOT runs integration tests with the snapshot build tag.
// FIPS runs the integration tests the requirefips build tag.
func (Test) Integration() {
	mg.SerialDeps(mg.F(mkDir, "build"), Test.IntegrationUp, Test.IntegrationRun, Test.IntegrationDown)
}

// IntegrationUp provisions the integration test environment with docker compose.
func (Test) IntegrationUp() error {
	return sh.RunV("docker", "compose", "-f", filepath.Join("dev-tools", "integration", "docker-compose.yml"), "--env-file", filepath.Join("dev-tools", "integration", ".env"), "up", "-d", "--wait", "--remove-orphans", "elasticsearch", "elasticsearch-remote")
}

// IntegrationRun runs integration tests.
// Assumes that the integration test environment is up.
// Produces an integration test output file in the build directory.
// SNAPSHOT runs integration tests with the snapshot build tag.
// FIPS runs the integration tests the requirefips build tag.
func (Test) IntegrationRun(ctx context.Context) error {
	env, err := readEnvFile(filepath.Join("dev-tools", "integration", ".env"))
	if err != nil {
		return fmt.Errorf("unable to read env file: %w", err)
	}

	// Gather tokens
	esToken, err := getServiceToken(ctx, "fleet-server", env["ELASTICSEARCH_USERNAME"], env["ELASTICSEARCH_PASSWORD"], "http://"+env["TEST_ELASTICSEARCH_HOSTS"])
	if err != nil {
		return err
	}
	esRemoteToken, err := getServiceToken(ctx, "fleet-server-remote", env["ELASTICSEARCH_USERNAME"], env["ELASTICSEARCH_PASSWORD"], "https://"+env["TEST_REMOTE_ELASTICSEARCH_HOST"])
	if err != nil {
		return err
	}

	// Get remote-elasticsearch CA from container.
	remoteCA, err := sh.OutputWith(map[string]string{"COMPOSE_PROJECT_NAME": "integration"}, "docker", "compose", "-f", filepath.Join("dev-tools", "integration", "docker-compose.yml"), "--env-file", filepath.Join("dev-tools", "integration", ".env"), "exec", "elasticsearch-remote", "/bin/bash", "-c", "cat /usr/share/elasticsearch/config/certs/ca/ca.crt | base64")
	if err != nil {
		return fmt.Errorf("unable to get remote-elasticsearch ca: %w", err)
	}

	env["ELASTICSEARCH_HOSTS"] = env["TEST_ELASTICSEARCH_HOSTS"]
	env["ELASTICSEARCH_SERVICE_TOKEN"] = esToken
	env["REMOTE_ELASTICSEARCH_SERVICE_TOKEN"] = esRemoteToken
	env["REMOTE_ELASTICSEARCH_CA_CRT_BASE64"] = remoteCA

	output, err := teeCommand(env, "go", "test", "-v", "-tags="+strings.Join([]string{"integration", getTagsString()}, ","), "-count=1", "-race", "-p", "1", "./...")
	err = errors.Join(err, os.WriteFile(filepath.Join("build", "test-int-"+runtime.GOOS+".out"), output, 0o644))
	return err
}

// IntegrationdDown destroys the integration test environment with docker compose.
func (Test) IntegrationDown() error {
	err := sh.RunV("docker", "compose", "-f", filepath.Join("dev-tools", "integration", "docker-compose.yml"), "--env-file", filepath.Join("dev-tools", "integration", ".env"), "down")
	return errors.Join(err, os.RemoveAll(".service_token_fleet-server"), os.RemoveAll(".service_toke_fleet-server-remote"))
}

// readEnvFile reads a the specified path as an env file and return a map of env vars.
// It assumes each line is either a comment, starting with #, or a KEY=VAL mapping.
func readEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %w", path, err)
	}
	defer f.Close()
	env := map[string]string{}
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") { // Skip comments
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		env[k] = v
	}
	return env, nil
}

// getServiceToken returns the contents of .service_token_ACCOUNT or gets a new token and persists it to .service_token_ACCOUNT.
func getServiceToken(ctx context.Context, account, username, password, host string) (string, error) {
	p, err := os.ReadFile(".service_token_" + account)
	if err != nil {
		esToken, err := requestServiceToken(ctx, username, password, host+"/_security/service/elastic/"+account+"/credential/token")
		if err != nil {
			return "", fmt.Errorf("unable to request new %s token: %w", account, err)
		}
		if err := os.WriteFile(".service_token_"+account, []byte(esToken), 0o640); err != nil {
			log.Printf("Unable to persist ES service token: %v", err)
		}
		return esToken, nil
	}
	return string(p), nil
}

// requestServiceToken requests a new token using the passed credentials at the specified url and return the token value.
func requestServiceToken(ctx context.Context, username, password, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("unable to create request: %w", err)
	}
	req.SetBasicAuth(username, password)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("expected 200 status, got %d", resp.StatusCode)
	}

	obj := struct {
		Token struct {
			Value string `json:"value"`
		} `json:"token"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return "", fmt.Errorf("error decoding response: %w", err)
	}
	return obj.Token.Value, nil
}

// Release checks that all release files are present within the build/distributions directory and asserts that the archive layouts are correct.
// PLATFORMS specifies the list of os/arch platforms to test.
// VERSION_QUALIFIER specifies if a version qualifier for the artifact versions should be used.
// SNAPSHOT runs release tests for a SNAPSHOT artifact
// FIPS runs the release test for a FIPS capable artifact - includes extra checks to see if the binary was compiled with the expected env vars, and tags.
func (Test) Release() error {
	pList := getPlatforms()
	namePrefix := "fleet-server-" + getVersion()
	if isFIPS() {
		namePrefix = "fleet-server-fips-" + getVersion()
	}
	for _, platform := range pList {
		osName, archName, _ := strings.Cut(platform, "/")
		if v, ok := platformRemap[platform]; ok {
			osName, archName, _ = strings.Cut(v, "/")
		}
		path := filepath.Join("build", "distributions", namePrefix+"-"+osName+"-"+archName+".tar.gz")
		if osName == "windows" {
			path = filepath.Join("build", "distributions", namePrefix+"-windows-"+archName+".zip")
		}
		_, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("unable to verify %s: %w", path, err)
		}
		if err := testArchive(path); err != nil {
			return err
		}
		path += ".sha512"
		_, err = os.Stat(path)
		if err != nil {
			return fmt.Errorf("unable to verify %s: %w", path, err)
		}
	}

	return nil
}

// testArchive unpacks the archive located in path and verifies its contents.
// If FIPS=true then the binary will be checked for fips capable indicators.
func testArchive(path string) error {
	dir, err := os.MkdirTemp("build", "release-test-*")
	if err != nil {
		return fmt.Errorf("unable to create temp dir for artifact extraction: %w", err)
	}
	defer os.RemoveAll(dir)
	var dName string
	var binary string

	switch {
	case strings.HasSuffix(path, ".tar.gz"):
		err := untar(path, dir)
		if err != nil {
			return fmt.Errorf("untar failure: %w", err)
		}
		dName = strings.TrimSuffix(filepath.Base(path), ".tar.gz")
		binary = binaryName
	case strings.HasSuffix(path, ".zip"):
		err := unzip(path, dir)
		if err != nil {
			return fmt.Errorf("unzip failure: %w", err)
		}
		dName = strings.TrimSuffix(filepath.Base(path), ".zip")
		binary = binaryExe
	default:
		return fmt.Errorf("unsupported archive type: %s", path)
	}

	// check extracted archive structure
	fi, err := os.Stat(filepath.Join(dir, dName))
	if err != nil {
		return fmt.Errorf("stat failed: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("expected %s to be a dir", filepath.Join(dir, dName))
	}
	// check binary
	binaryPath := filepath.Join(dir, dName, binary)
	fi, err = os.Stat(binaryPath)
	if err != nil {
		return fmt.Errorf("stat failed: %w", err)
	}
	if fi.Size() == 0 {
		return fmt.Errorf("zero len fleet-server detected")
	}
	if isFIPS() {
		if err := checkFIPSBinary(binaryPath); err != nil {
			return fmt.Errorf("binary failed fips capable markers check: %w", err)
		}
	}
	return nil
}

// untar extracts the sourceFile to the destinationDir.
func untar(sourceFile, destinationDir string) error {
	file, err := os.Open(sourceFile)
	if err != nil {
		return err
	}
	defer file.Close()

	var fileReader io.ReadCloser = file

	if strings.HasSuffix(sourceFile, ".gz") {
		if fileReader, err = gzip.NewReader(file); err != nil {
			return err
		}
		defer fileReader.Close()
	}

	tarReader := tar.NewReader(fileReader)

	for {
		header, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		//nolint:gosec // G305: file traversal, no user input
		path := filepath.Join(destinationDir, header.Name)
		if !strings.HasPrefix(path, destinationDir) {
			return fmt.Errorf("illegal file path in tar: %v", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(path, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}

			writer, err := os.Create(path)
			if err != nil {
				return err
			}

			//nolint:gosec // decompression bomb, no user input
			if _, err = io.Copy(writer, tarReader); err != nil {
				return err
			}

			if err = os.Chmod(path, os.FileMode(header.Mode)); err != nil {
				return err
			}

			if err = writer.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(header.Linkname, path); err != nil {
				return fmt.Errorf("error creating symlink %s pointing to %s: %w", path, header.Linkname, err)
			}

		default:
			return fmt.Errorf("unable to untar type=%c in file=%s", header.Typeflag, path)
		}
	}

	return nil
}

// unzip extracts the sourceFile to the destinationDir.
func unzip(sourceFile, destinationDir string) error {
	r, err := zip.OpenReader(sourceFile)
	if err != nil {
		return err
	}
	defer r.Close()

	if err = os.MkdirAll(destinationDir, 0o755); err != nil {
		return err
	}

	extractAndWriteFile := func(f *zip.File) error {
		innerFile, err := f.Open()
		if err != nil {
			return err
		}
		defer innerFile.Close()

		//nolint:gosec // G305 zip traversal, no user input
		path := filepath.Join(destinationDir, f.Name)
		if !strings.HasPrefix(path, destinationDir) {
			return fmt.Errorf("illegal file path in zip: %v", f.Name)
		}

		if f.FileInfo().IsDir() {
			return os.MkdirAll(path, f.Mode())
		}

		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		defer out.Close()

		//nolint:gosec // DoS vulnerability, no user input
		if _, err = io.Copy(out, innerFile); err != nil {
			return err
		}

		return out.Close()
	}

	for _, f := range r.File {
		err := extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}

	return nil
}

// checkFIPSBinary ensures the binary located at path has fips capable markers set.
func checkFIPSBinary(path string) error {
	log.Printf("Verifiying binary in %q for FIPS capable markers.", path)
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("unable to read buildinfo: %w", err)
	}
	var checkLinks, foundTags, foundExperiment bool

	for _, setting := range info.Settings {
		switch setting.Key {
		case "-tags":
			foundTags = true
			if !strings.Contains(setting.Value, "requirefips") {
				return fmt.Errorf("requirefips tag not found in %s", setting.Value)
			}
			continue
		case "GOEXPERIMENT":
			foundExperiment = true
			if !strings.Contains(setting.Value, "systemcrypto") {
				return fmt.Errorf("did not find GOEXPIRIMENT=systemcrypto")
			}
			continue
		case "-ldflags":
			if !strings.Contains(setting.Value, "-s") {
				checkLinks = true
				continue
			}
		}
	}

	if !foundTags {
		return fmt.Errorf("did not find build tags")
	}
	if !foundExperiment {
		return fmt.Errorf("did not find GOEXPERIMENT")
	}
	if checkLinks {
		log.Println("Binary is not stripped, checking symbols table.")
		output, err := sh.Output("go", "tool", "nm", path)
		if err != nil {
			return fmt.Errorf("go tool nm failed: %w", err)
		}
		if runtime.GOOS == "linux" && !strings.Contains(output, "OpenSSL_version") { // TODO may need different check for windows/darwin
			return fmt.Errorf("failed to find OpenSSL symbol links within binary")
		}
	}
	return nil
}

// JunitReport produces junit report files from test-output files in the build dir.
func (Test) JunitReport() error {
	return filepath.WalkDir("build", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walkdir error: %w", err)
		}
		if d.IsDir() && name != "build" { // Skip non-parent directories
			return filepath.SkipDir
		}
		if !strings.HasSuffix(name, ".out") {
			return nil
		}

		srcFile, err := os.Open(name)
		if err != nil {
			return fmt.Errorf("unable to open source file: %w", err)
		}
		defer srcFile.Close()
		var output bytes.Buffer
		var stderr bytes.Buffer

		cmd := exec.Command("go", "tool", "-modfile", filepath.Join("dev-tools", "go.mod"), "github.com/jstemmer/go-junit-report")
		cmd.Stdin = srcFile
		cmd.Stdout = &output
		cmd.Stderr = &stderr

		err = cmd.Run()
		if err != nil {
			log.Printf("Junit report stderr: %s", stderr.String())
		}
		return errors.Join(err, os.WriteFile(name+".xml", output.Bytes(), 0o644))
	})
}

// All runs unit and integration tests and produces junit reports for all the tests.
// SNAPSHOT adds the snapshot build tag.
// FIPS adds the requirefips build tag.
func (Test) All() {
	mg.SerialDeps(mg.F(mkDir, "build"), Test.Unit, Test.Integration, Test.JunitReport)
}

// Benchmark runs the included benchmarks
// Produces a benchmark file in the build directory.
// SNAPSHOT adds the snapshot build tag.
// FIPS adds the requirefips build tag.
// BENCHMARK_FILTER can be used to filter what benchmarks run.
// BENCHMARK_ARGS can be used to change what is being benchmarked. Default: -count=10 -benchtime=3s -benchmem.
// BENCH_BASE can be used to change the output file name.
func (Test) Benchmark() error {
	mg.Deps(mg.F(mkDir, "build"))
	bFilter := "Bench"
	if v, ok := os.LookupEnv(envBenchmarkFilter); ok && v != "" {
		bFilter = v
	}
	benchmarkArgs := "-count=10 -benchtime=3s -benchmem"
	if v, ok := os.LookupEnv(envBenchmarkArgs); ok && v != "" {
		benchmarkArgs = v
	}
	args := []string{"test", "-bench=" + bFilter, "-tags=" + getTagsString(), "-run=" + bFilter}
	args = append(args, strings.Split(benchmarkArgs, " ")...)
	args = append(args, "./...")

	output, err := teeCommand(environMap(), "go", args...)

	outFile := "benchmark-" + getCommitID() + ".out"
	if v, ok := os.LookupEnv(envBenchBase); ok && v != "" {
		outFile = v
	}
	err = errors.Join(err, os.WriteFile(filepath.Join("build", outFile), output, 0o644))
	return err
}

// Benchstat runs the benchstat tool to compare benchmarks.
// BENCH_BASE can be used to specify the base input file name.
// BENCH_NEXT can be used tp specify the comparison input file name.
func (Test) Benchstat() error {
	base := filepath.Join("build", "benchmark-"+getCommitID()+".out")
	if v, ok := os.LookupEnv(envBenchBase); ok && v != "" {
		base = v
	}
	args := []string{
		"tool",
		"-modfile",
		filepath.Join("dev-tools", "go.mod"),
		"golang.org/x/perf/cmd/benchstat",
		base,
	}
	if v, ok := os.LookupEnv(envBenchNext); ok && v != "" {
		args = append(args, v)
	}
	return sh.RunV("go", args...)
}

// E2e provisions the e2e test environment with docker compose, runs e2e tests, then destroys the environment.
// The e2e test environment is providisioned ontop of the integration test environment.
// The e2e test will attempt to force DEV and SNAPSHOT to true, and set DOCKER_IMAGE to fleet-server-e2e-agent.
// The PLATFORMS list will also be set to: [linux/arch, os/arch].
// FIPS can be used to test a FIPS capable fleet-server (support in progress).
func (Test) E2e() {
	os.Setenv(envDev, "true")
	os.Setenv(envSnapshot, "true")

	// Set PLATFORMS to linux/$GOARCH + a binary for the local system
	pList := []string{
		runtime.GOOS + "/" + runtime.GOARCH,
		"linux/" + runtime.GOARCH,
	}
	os.Setenv(envPlatforms, strings.Join(slices.Compact(pList), ","))
	mg.SerialDeps(mg.F(mkDir, "build"), mg.F(mkDir, filepath.Join("build", "e2e-cover")), Build.Cover, Docker.Image, Docker.CustomAgentImage, Test.E2eCerts, Test.E2eUp, Test.E2eRun, Test.E2eDown, Test.ConvertCoverage)
}

// E2eCerts generates the e2e test CA and certs.
// TODO use go instead of openssl?
func (Test) E2eCerts() error {
	mg.SerialDeps(mg.F(mkDir, certDir), createCA, createPassphrase, createPrivateKey)

	openSSLVersion, err := sh.Output("openssl", "version")
	if err != nil {
		return fmt.Errorf("unable to get openssl version: %w", err)
	}
	verRegExp := regexp.MustCompile(`^OpenSSL ([\d]+)\.`)
	matches := verRegExp.FindStringSubmatch(openSSLVersion)
	// Ensure PKCS#1 format is used (https://github.com/elastic/elastic-agent-libs/issues/134)
	if len(matches) == 2 {
		i, err := strconv.Atoi(matches[1])
		if err != nil {
			mg.Deps(mg.F(createPKCS1Key, false))
		} else if i >= 3 {
			mg.Deps(mg.F(createPKCS1Key, true))
		} else {
			mg.Deps(mg.F(createPKCS1Key, false))
		}
	} else {
		mg.Deps(mg.F(createPKCS1Key, false))
	}
	mg.SerialDeps(createFleetCert, validateCerts, validateCertUnpacking)
	return nil
}

func createCA() error {
	err := sh.Run("openssl",
		"req", "-x509",
		"-sha256",
		"-days", "356",
		"-nodes",
		"-newkey", "rsa:2048",
		"-subj", "/CN=e2e-test-ca",
		"-keyout", caKeyFile,
		"-out", caFile,
	)
	if err != nil {
		return fmt.Errorf("failed to create CA: %w", err)
	}
	return nil
}

func createPassphrase() error {
	return os.WriteFile(passFile, []byte("abcd1234"), 0o640)
}

func createPrivateKey() error {
	err := sh.Run("openssl",
		"genpkey",
		"-algorithm", "RSA",
		"-aes-128-cbc",
		"-pkeyopt", "rsa_keygen_bits:2048",
		"-pass", "file:"+passFile,
		"-out", filepath.Join(certDir, "fleet-server-key"),
	)
	if err != nil {
		return fmt.Errorf("unable to create encrypted private key: %w", err)
	}
	return nil
}

func createPKCS1Key(traditional bool) error {
	args := []string{"rsa", "-aes-128-cbc"}
	if traditional {
		args = append(args, "-traditional")
	}
	args = append(args,
		"-in", filepath.Join(certDir, "fleet-server-key"),
		"-out", keyFile,
		"-passin", "pass:abcd1234",
		"-passout", "file:"+passFile,
	)
	err := sh.Run("openssl", args...)
	if err != nil {
		return fmt.Errorf("failed to create pkcs1: %w", err)
	}
	return nil
}

func createFleetCert() error {
	err := sh.Run("openssl",
		"req", "-new",
		"-key", keyFile,
		"-passin", "file:"+passFile,
		"-subj", "/CN=localhost",
		"-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:fleet-server",
		"-out", filepath.Join(certDir, "fleet-server.csr"),
	)
	if err != nil {
		return fmt.Errorf("csr error: %w", err)
	}

	f, err := os.CreateTemp(certDir, "extFile-*")
	if err != nil {
		return fmt.Errorf("unable to create temp file: %w", err)
	}
	fName := f.Name()
	defer os.Remove(fName)
	defer f.Close()
	if _, err := fmt.Fprintln(f, "subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:fleet-server"); err != nil {
		return fmt.Errorf("unable to write file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("unable to persist temp file to disk: %w", err)
	}

	err = sh.Run("openssl",
		"x509", "-req",
		"-in", filepath.Join(certDir, "fleet-server.csr"),
		"-days", "356",
		"-extfile", fName,
		"-CA", caFile,
		"-CAkey", caKeyFile,
		"-CAcreateserial",
		"-out", certFile,
	)
	if err != nil {
		return fmt.Errorf("cert error: %w", err)
	}
	return nil
}

func validateCerts() error {
	output, err := sh.Output("openssl",
		"verify", "-verbose",
		"-CAfile", caFile,
		certFile,
	)
	if err != nil {
		fmt.Println(output)
		return fmt.Errorf("unable to verify fleet-server cert with openssl: %w", err)
	}
	output, err = sh.Output("openssl",
		"rsa", "-check", "-noout",
		"-in", keyFile,
		"-passin", "file:"+passFile,
	)
	if err != nil {
		fmt.Println(output)
		return fmt.Errorf("unable to verify fleet-server key with openssl: %w", err)
	}
	return nil
}

func validateCertUnpacking() error {
	config := tlscommon.Config{
		CAs: []string{
			caFile,
		},
		Certificate: tlscommon.CertificateConfig{
			Certificate:    certFile,
			Key:            keyFile,
			PassphrasePath: passFile,
		},
	}

	logger := logp.NewLogger("certs")
	_, err := tlscommon.LoadTLSConfig(&config, logger)
	if err != nil {
		log.Printf("tlscommon load error: %v", err)
		passphrase, err := os.ReadFile(passFile)
		if err != nil {
			return fmt.Errorf("unable to read passphrase: %w", err)
		}
		keyPEM, err := tlscommon.ReadPEMFile(logp.NewLogger("certs"), keyFile, string(passphrase))
		if err != nil {
			return fmt.Errorf("unable to read PEMFile: %w", err)
		}

		keyDER, _ := pem.Decode(keyPEM)
		log.Println("Key DER Block Type:", keyDER.Type)

		_, err1 := x509.ParsePKCS1PrivateKey(keyDER.Bytes)
		_, err8 := x509.ParsePKCS8PrivateKey(keyDER.Bytes)
		_, errEC := x509.ParseECPrivateKey(keyDER.Bytes)
		return errors.Join(err1, err8, errEC)
	}
	return nil
}

// E2eUp provisions the e2e test envionment with docker compose.
// Attempts to force DEV and SNAPSHOT to true.
func (Test) E2eUp(ctx context.Context) error {
	os.Setenv(envDev, "true")
	os.Setenv(envSnapshot, "true")
	mg.SerialDeps(mg.F(mkDir, "build"), mg.F(mkDir, filepath.Join("build", "e2e-cover")), Test.IntegrationUp, Build.Cover, Docker.Image, Docker.CustomAgentImage, Test.E2eCerts)
	env, err := readEnvFile(filepath.Join("dev-tools", "integration", ".env"))
	if err != nil {
		return fmt.Errorf("unable to read env file: %w", err)
	}
	kibanaToken, err := getServiceToken(ctx, "kibana", env["ELASTICSEARCH_USERNAME"], env["ELASTICSEARCH_PASSWORD"], "http://"+env["TEST_ELASTICSEARCH_HOSTS"])
	if err != nil {
		return fmt.Errorf("unable to get kibana service token: %w", err)
	}
	apmKey, err := getAPMKey(ctx, env["ELASTICSEARCH_USERNAME"], env["ELASTICSEARCH_PASSWORD"], "http://"+env["TEST_ELASTICSEARCH_HOSTS"], strings.NewReader(apmRole))
	if err != nil {
		return fmt.Errorf("unable to key apm-server's api_key: %w", err)
	}

	if err := sh.RunWithV(map[string]string{"KIBANA_TOKEN": kibanaToken, "APM_KEY": apmKey},
		"docker", "compose",
		"-f", filepath.Join("dev-tools", "e2e", "docker-compose.yml"),
		"--env-file", filepath.Join("dev-tools", "integration", ".env"),
		"up", "-d",
		"--remove-orphans", "kibana",
		"--remove-orphans", "apm-server",
		"--wait",
	); err != nil {
		return fmt.Errorf("unable to bring e2e env up: %w", err)
	}
	return waitForAPMServer(ctx)
}

// getAPMKey returns the contents of .apm_server_api_key or gets a new ApiKey and persists it to .apm_server_api_key.
func getAPMKey(ctx context.Context, username, password, host string, body io.Reader) (string, error) {
	p, err := os.ReadFile(".apm_server_api_key")
	if err != nil {
		key, err := requestAPIKey(ctx, username, password, host+"/_security/api_key", body)
		if err != nil {
			return "", fmt.Errorf("unable to request new apm key: %w", err)
		}
		if err := os.WriteFile(".apm_server_api_key", []byte(key), 0o640); err != nil {
			log.Printf("Unable to persist API key for apm-server: %v", err)
		}
		return key, nil
	}
	return string(p), nil
}

// requestAPIKey requests a new ApiKey using the passed credenials from the specied url. The passed body will be used for the request.
func requestAPIKey(ctx context.Context, username, password, url string, body io.Reader) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return "", fmt.Errorf("unable to create request: %w", err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("expected 200 status, got %d", resp.StatusCode)
	}

	obj := struct {
		ID     string `json:"id"`
		ApiKey string `json:"api_key"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return "", fmt.Errorf("unable to decode response: %w", err)
	}
	return obj.ID + ":" + obj.ApiKey, nil
}

// waitForAPMServer waits unit the apm-server is online and healthy.
func waitForAPMServer(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute*5)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:8200", nil)
	if err != nil {
		return fmt.Errorf("unable to make request: %w", err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("Request error: %v", err)
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			log.Printf("Waiting for apm-server to return 200, got: %d.", resp.StatusCode)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// E2eRun runs the e2e tests.
// Assumes that the test environment has been provisioned with test:e2eUp.
// Produces a e2e test report file in the build directory, and may provide go coverage doata in build/e2e-cover.
// Attempts to force DEV and SNAPSHOT to true.
// FIPS can be used to test a FIPS capable fleet-server (support in progress).
func (Test) E2eRun(ctx context.Context) error {
	os.Setenv(envDev, "true")
	os.Setenv(envSnapshot, "true")
	env, err := readEnvFile(filepath.Join("dev-tools", "integration", ".env"))
	if err != nil {
		return fmt.Errorf("unable to read env file: %w", err)
	}
	esToken, err := getServiceToken(ctx, "fleet-server", env["ELASTICSEARCH_USERNAME"], env["ELASTICSEARCH_PASSWORD"], "http://"+env["TEST_ELASTICSEARCH_HOSTS"])
	if err != nil {
		return err
	}
	p, err := os.ReadFile(filepath.Join("build", "custom-image"))
	if err != nil {
		return fmt.Errorf("unable to get agent custom image: %w", err)
	}
	image := dockerImage
	if isFIPS() {
		image += "-fips"
	}
	tag := getVersion()
	if isDEV() { // tags can have an addtional -dev
		tag += "-dev"
	}
	if v, ok := os.LookupEnv(envDockerTag); ok && v != "" {
		tag = v
	}

	cmdEnv := os.Environ()
	for k, v := range env {
		cmdEnv = append(cmdEnv, k+"="+v)
	}
	cmdEnv = append(cmdEnv,
		"ELASTICSEARCH_HOSTS="+env["TEST_ELASTICSEARCH_HOSTS"],
		"ELASTICSEARCH_SERVICE_TOKEN="+esToken,
		"AGENT_E2E_IMAGE="+string(p),
		"STANDALONE_E2E_IMAGE="+image+":"+tag,
		"CGO_ENABLED=1",
	)

	var b bytes.Buffer
	w := io.MultiWriter(&b, os.Stdout)

	cmd := exec.Command("go", "test", "-v", "-timeout", "30m", "-tags="+strings.Join([]string{"e2e", getTagsString()}, ","), "-count=1", "-race", "-p", "1", "./...")
	cmd.Dir = "testing"
	cmd.Env = cmdEnv
	cmd.Stdout = w
	cmd.Stderr = w
	err = cmd.Run()
	err = errors.Join(err, os.WriteFile(filepath.Join("build", "test-e2e-"+runtime.GOOS+".out"), b.Bytes(), 0o644))
	return err
}

// E2eDown destroys the e2e and integration test environment with docker compose.
func (Test) E2eDown() error {
	err := sh.RunWithV(map[string]string{"KIBANA_TOKEN": "supress-warning", "APM_KEY": "supress-warning"}, "docker", "compose", "-f", filepath.Join("dev-tools", "e2e", "docker-compose.yml"), "--env-file", filepath.Join("dev-tools", "integration", ".env"), "down")
	if err != nil {
		return fmt.Errorf("failed to stop e2e environment: %w", err)
	}
	if err := errors.Join(
		os.RemoveAll(".service_token_kibana"),
		os.RemoveAll(".apm_server_api_key"),
	); err != nil {
		return err
	}
	mg.Deps(Test.IntegrationDown)
	return nil
}

// ConvertCoverage formats coverage data emitted by coverage-enabled binaries in e2e tests.
func (Test) ConvertCoverage() error {
	return sh.RunV("go", "tool", "covdata", "textfmt", "-i="+filepath.Join("build", "e2e-cover"), "-o="+filepath.Join("build", "e2e-coverage.out"))
}

// FipsProviderUnit runs unit tests with all FIPS env vars and tags.
// It requires microsoft/go and a FIPS provider on the system.
// Produces a unit test output file, and test coverage file in the build directory.
func (Test) FipsProviderUnit() error {
	mg.Deps(mg.F(mkDir, "build"))
	os.Setenv(envFIPS, "true")
	if !isFIPS() {
		return fmt.Errorf("FIPS must be set to true.")
	}
	env := environMap()
	addFIPSEnvVars(env)
	output, err := teeCommand(env, "go", "test", "-tags="+getTagsString(), "-v", "-race", "-coverprofile="+filepath.Join("build", "coverage-fips-provider-"+runtime.GOOS+".out"), "./...")
	err = errors.Join(err, os.WriteFile(filepath.Join("build", "test-unit-fips-provider-"+runtime.GOOS+".out"), output, 0o644))
	return err
}

// CloudE2E provisions a cloud deployment, tests the remote fleet-server instance, then destroys the deployment.
// The cloud ECH deployment is provisioned in the cloud first test region using a custom agent image that has it's fleet-server replaced.
// SNAPSHOT will be set to true, PLATFORMS will be set to: [linux/amd64], DOCKER_IMAGE will be set to docker.elastic.co/beats-ci/elastic-agent-cloud-fleet, and DOCKER_IMAGE_TAG will be set to one that reflects the git commit and current Unix epoch time.
func (Test) CloudE2E() {
	os.Setenv(envSnapshot, "true")
	os.Setenv(envPlatforms, "linux/amd64")
	os.Setenv(envDockerImage, dockerImage)
	os.Setenv(envDockerTag, fmt.Sprintf("git-%s-%d", getCommitID(), time.Now().Unix()))
	mg.SerialDeps(mg.F(mkDir, "build"), Docker.Cover, Docker.CustomAgentImage, Docker.Push, Test.CloudE2EUp, Test.CloudE2ERun, Test.CloudE2EDown)
}

// CloudE2EUp provisions the cloud deployment for testing.
// DOCKER_IMAGE can be used to specify the custom integration server image.
// DOCKER_IMAGE_TAG can be used to specify the tag of the custom integration server.
func (Test) CloudE2EUp() error {
	os.Setenv(envSnapshot, "true")
	imageName := dockerImage
	imageTag := getVersion()

	if name, ok := os.LookupEnv(envDockerImage); ok && name != "" {
		imageName = name
	}
	if tag, ok := os.LookupEnv(envDockerTag); ok && tag != "" {
		imageTag = tag
	}

	initCmd := exec.Command("terraform", "init")
	initCmd.Dir = filepath.Join("dev-tools", "cloud", "terraform")
	initOut, err := initCmd.CombinedOutput()
	if err != nil {
		log.Printf("terraform init output: %s", string(initOut))
		return fmt.Errorf("terraform init failed: %w", err)
	}
	args := []string{
		"apply",
		"-auto-approve",
		"-var", "git_commit=" + getCommitID(),
		"-var", "elastic_agent_docker_image=" + imageName + ":" + imageTag,
	}
	log.Printf("Running terraform %s", strings.Join(args, " "))
	applyCmd := exec.Command("terraform", args...)
	applyCmd.Dir = filepath.Join("dev-tools", "cloud", "terraform")
	applyCmd.Stdout = os.Stdout
	applyCmd.Stderr = os.Stderr
	return applyCmd.Run()
}

// CloudE2EDown destroys the testing cloud deployment.
func (Test) CloudE2EDown() error {
	imageName := dockerImage
	imageTag := getVersion()

	if name, ok := os.LookupEnv(envDockerImage); ok && name != "" {
		imageName = name
	}
	if tag, ok := os.LookupEnv(envDockerTag); ok && tag != "" {
		imageTag = tag
	}

	args := []string{"destroy", "-auto-approve", "-var", "elastic_agent_docker_image=" + imageName + ":" + imageTag}
	log.Printf("Running terraform %s", strings.Join(args, " "))
	cmd := exec.Command("terraform", args...)
	cmd.Dir = filepath.Join("dev-tools", "cloud", "terraform")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// CloudE2ERun runs tests against the remote cloud deployment.
func (Test) CloudE2ERun() error {
	fleetURL, err := sh.Output("terraform", "output", "--raw", "--state="+filepath.Join("dev-tools", "cloud", "terraform", "terraform.tfstate"), "fleet_url")
	if err != nil {
		return fmt.Errorf("unable to retrive fleet-server cloud url: %w", err)
	}

	kibanaURL, err := sh.Output("terraform", "output", "--raw", "--state="+filepath.Join("dev-tools", "cloud", "terraform", "terraform.tfstate"), "kibana_url")
	if err != nil {
		return fmt.Errorf("unable to retrive kibana cloud url: %w", err)
	}

	user, err := sh.Output("terraform", "output", "--raw", "--state="+filepath.Join("dev-tools", "cloud", "terraform", "terraform.tfstate"), "elasticsearch_username")
	if err != nil {
		return fmt.Errorf("unable to retrive es username: %w", err)
	}
	pass, err := sh.Output("terraform", "output", "--raw", "--state="+filepath.Join("dev-tools", "cloud", "terraform", "terraform.tfstate"), "elasticsearch_password")
	if err != nil {
		return fmt.Errorf("unable to retrive es password: %w", err)
	}

	var b bytes.Buffer
	w := io.MultiWriter(&b, os.Stdout)
	cmd := exec.Command("go", "test", "-v", "-timeout", "30m", "-tags=cloude2e", "-count=1", "-p", "1", "./...")
	cmd.Dir = "testing"
	cmd.Env = append(os.Environ(),
		"FLEET_SERVER_URL="+fleetURL,
		"KIBANA_URL="+kibanaURL,
		"ELASTIC_USER="+user,
		"ELASTIC_PASS="+pass,
	)
	cmd.Stdout = w
	cmd.Stderr = w
	err = cmd.Run()
	err = errors.Join(err, os.WriteFile(filepath.Join("build", "test-cloude2e.out"), b.Bytes(), 0o644))
	return err
}
