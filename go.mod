module fleet

go 1.14

require (
	github.com/dgraph-io/ristretto v0.0.3
	github.com/elastic/beats/v7 v7.10.0
	github.com/elastic/go-elasticsearch/v8 v8.0.0-20200728144331-527225d8e836
	github.com/elastic/go-ucfg v0.8.3
	github.com/gofrs/uuid v3.3.0+incompatible
	github.com/google/go-cmp v0.4.0
	github.com/google/uuid v1.1.2-0.20190416172445-c2e93f3ae59f
	github.com/julienschmidt/httprouter v1.3.0
	github.com/mitchellh/mapstructure v1.3.3
	github.com/rs/zerolog v1.19.0
	github.com/spf13/cobra v0.0.5
	github.com/stretchr/testify v1.6.1
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e
)

replace (
	github.com/Shopify/sarama => github.com/elastic/sarama v1.19.1-0.20200629123429-0e7b69039eec
	github.com/dop251/goja => github.com/andrewkroh/goja v0.0.0-20190128172624-dd2ac4456e20
	github.com/fsnotify/fsevents => github.com/elastic/fsevents v0.0.0-20181029231046-e1d381a4d270
)
