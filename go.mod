module github.com/elastic/fleet-server/v7

<<<<<<< HEAD
go 1.23.0
=======
go 1.24.3
>>>>>>> 9dd0054 (Update to go 1.24.3 (#4891))

require (
	github.com/Pallinder/go-randomdata v1.2.0
	github.com/dgraph-io/ristretto v0.2.0
	github.com/elastic/beats/v7 v7.17.23-0.20240725133810-bd0ffc1af3bb
	github.com/elastic/elastic-agent-client/v7 v7.8.1
	github.com/elastic/go-elasticsearch/v7 v7.16.0
	github.com/elastic/go-ucfg v0.8.8
	github.com/gofrs/uuid v4.4.0+incompatible
	github.com/google/go-cmp v0.7.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-version v1.7.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/julienschmidt/httprouter v1.3.0
	github.com/mailru/easyjson v0.9.0
	github.com/miolini/datacounter v1.0.3
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58
	github.com/pkg/errors v0.9.1
	github.com/rs/xid v1.6.0
	github.com/rs/zerolog v1.27.0
	github.com/spf13/cobra v1.7.0
	github.com/stretchr/testify v1.8.4
	go.uber.org/zap v1.27.0
	golang.org/x/sync v0.12.0
	golang.org/x/time v0.11.0
)

require (
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/elastic/elastic-agent-libs v0.7.2 // indirect
	github.com/elastic/go-licenser v0.4.1 // indirect
	github.com/elastic/go-structform v0.0.9 // indirect
	github.com/elastic/go-sysinfo v1.14.0 // indirect
	github.com/elastic/go-windows v1.0.1 // indirect
	github.com/elastic/gosigar v0.14.2 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/gofrs/flock v0.7.2-0.20190320160742-5135e617513b // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jcchavezs/porto v0.6.0 // indirect
	github.com/joeshaw/multierror v0.0.0-20140124173710-69b34d4ec901 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/procfs v0.13.0 // indirect
	github.com/santhosh-tekuri/jsonschema v1.2.4 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.elastic.co/apm v1.15.0 // indirect
	go.elastic.co/ecszap v1.0.2 // indirect
	go.elastic.co/fastjson v1.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/exp v0.0.0-20231127185646-65229373498e // indirect
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/mod v0.20.0 // indirect
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/tools v0.24.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240415180920-8c6c420018be // indirect
	google.golang.org/grpc v1.63.2 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	howett.net/plist v1.0.1 // indirect
)

replace (
	github.com/Shopify/sarama => github.com/elastic/sarama v1.19.1-0.20200629123429-0e7b69039eec
	github.com/dop251/goja => github.com/andrewkroh/goja v0.0.0-20190128172624-dd2ac4456e20
	github.com/fsnotify/fsevents => github.com/elastic/fsevents v0.0.0-20181029231046-e1d381a4d270
)
