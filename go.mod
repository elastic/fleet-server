module github.com/elastic/fleet-server/v7

go 1.17

require (
	github.com/Pallinder/go-randomdata v1.2.0
	github.com/dgraph-io/ristretto v0.1.0
	github.com/elastic/beats/v7 v7.0.0-alpha2.0.20211207150041-4641f759226c
	github.com/elastic/elastic-agent-client/v7 v7.0.0-20210922110810-e6f1f402a9ed
	github.com/elastic/go-elasticsearch/v7 v7.15.1
	github.com/elastic/go-ucfg v0.8.4
	github.com/gofrs/uuid v4.2.0+incompatible
	github.com/google/go-cmp v0.5.6
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-version v1.3.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/julienschmidt/httprouter v1.3.0
	github.com/mailru/easyjson v0.7.7
	github.com/miolini/datacounter v1.0.2
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58
	github.com/pkg/errors v0.9.1
	github.com/rs/xid v1.2.1
	github.com/rs/zerolog v1.22.0
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.7.0
	go.elastic.co/apm v1.14.0
	go.elastic.co/apm/module/apmelasticsearch v1.14.0
	go.uber.org/zap v1.19.1
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/time v0.0.0-20210611083556-38a9dc6acbc6
)

require go.elastic.co/ecszerolog v0.1.0

require (
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/elastic/go-licenser v0.4.0 // indirect
	github.com/elastic/go-structform v0.0.9 // indirect
	github.com/elastic/go-sysinfo v1.7.1 // indirect
	github.com/elastic/go-windows v1.0.1 // indirect
	github.com/elastic/gosigar v0.14.2 // indirect
	github.com/gofrs/flock v0.8.1 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/joeshaw/multierror v0.0.0-20140124173710-69b34d4ec901 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/magefile/mage v1.11.0 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/santhosh-tekuri/jsonschema v1.2.4 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.elastic.co/apm/module/apmhttp v1.14.0 // indirect
	go.elastic.co/fastjson v1.1.0 // indirect
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/mod v0.5.1 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

require (
	github.com/fatih/color v1.13.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/jcchavezs/porto v0.4.0 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	go.elastic.co/apm/module/apmhttprouter v1.14.0
	go.elastic.co/ecszap v1.0.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.7.0 // indirect
	golang.org/x/crypto v0.0.0-20211202192323-5770296d904e // indirect
	golang.org/x/net v0.0.0-20211207213349-853792941377 // indirect
	golang.org/x/sys v0.0.0-20211205182925-97ca703d548d // indirect
	golang.org/x/tools v0.1.8 // indirect
	google.golang.org/genproto v0.0.0-20211207154714-918901c715cf // indirect
	google.golang.org/grpc v1.42.0 // indirect
	howett.net/plist v1.0.0 // indirect
)

replace (
	github.com/Shopify/sarama => github.com/elastic/sarama v1.19.1-0.20200629123429-0e7b69039eec
	github.com/dop251/goja => github.com/andrewkroh/goja v0.0.0-20190128172624-dd2ac4456e20
	github.com/fsnotify/fsevents => github.com/elastic/fsevents v0.0.0-20181029231046-e1d381a4d270
)
