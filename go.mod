module github.com/traefik/traefik/v2

go 1.22

require (
	github.com/BurntSushi/toml v1.3.2
	github.com/ExpediaDotCom/haystack-client-go v0.0.0-20190315171017-e7edbdf53a61
	github.com/Masterminds/sprig v2.22.0+incompatible
	github.com/NYTimes/gziphandler v1.1.1
	github.com/abbot/go-http-auth v0.0.0-00010101000000-000000000000
	github.com/abronan/valkeyrie v0.0.0-20200127174252-ef4277a138cd
	github.com/aws/aws-sdk-go v1.30.20
	github.com/cenkalti/backoff/v4 v4.0.2
	github.com/containous/alice v0.0.0-20181107144136-d83ebdd94cbd
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/cli v0.0.0-20200221155518-740919cc7fc0
	github.com/docker/docker v0.0.0-00010101000000-000000000000
	github.com/docker/go-connections v0.4.0
	github.com/eapache/channels v1.1.0
	github.com/elazarl/go-bindata-assetfs v1.0.0
	github.com/fatih/structs v1.1.0
	github.com/gambol99/go-marathon v0.0.0-20180614232016-99a156b96fb2
	github.com/go-acme/lego/v4 v4.1.0
	github.com/go-check/check v0.0.0-00010101000000-000000000000
	github.com/go-kit/kit v0.10.1-0.20200915143503-439c4d2ed3ea
	github.com/golang/protobuf v1.5.0
	github.com/google/go-github/v28 v28.1.1
	github.com/gorilla/mux v1.7.3
	github.com/gorilla/websocket v1.4.2
	github.com/hashicorp/consul/api v1.3.0
	github.com/hashicorp/go-version v1.2.0
	github.com/influxdata/influxdb1-client v0.0.0-20191209144304-8bf82d3c094d
	github.com/instana/go-sensor v1.5.1
	github.com/libkermit/compose v0.0.0-20171122111507-c04e39c026ad
	github.com/libkermit/docker v0.0.0-20171122101128-e6674d32b807
	github.com/libkermit/docker-check v0.0.0-20171122104347-1113af38e591
	github.com/mailgun/ttlmap v0.0.0-20170619185759-c1c17f74874f
	github.com/miekg/dns v1.1.31
	github.com/mitchellh/copystructure v1.0.0
	github.com/mitchellh/hashstructure v1.0.0
	github.com/mitchellh/mapstructure v1.3.3
	github.com/opentracing/opentracing-go v1.1.0
	github.com/openzipkin-contrib/zipkin-go-opentracing v0.4.5
	github.com/openzipkin/zipkin-go v0.2.2
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pires/go-proxyproto v0.3.1
	github.com/pmezard/go-difflib v1.0.0
	github.com/prometheus/client_golang v1.3.0
	github.com/prometheus/client_model v0.1.0
	github.com/rancher/go-rancher-metadata v0.0.0-20200311180630-7f4c936a06ac
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.8.4
	github.com/stvp/go-udp-testing v0.0.0-20191102171040-06b61409b154
	github.com/traefik/paerser v0.1.0
	github.com/traefik/yaegi v0.9.7
	github.com/uber/jaeger-client-go v2.25.0+incompatible
	github.com/uber/jaeger-lib v2.2.0+incompatible
	github.com/unrolled/render v1.0.2
	github.com/unrolled/secure v1.0.7
	github.com/vdemeester/shakers v0.1.0
	github.com/vulcand/oxy v1.1.0
	github.com/vulcand/predicate v1.1.0
	go.elastic.co/apm v1.7.0
	go.elastic.co/apm/module/apmot v1.7.0
	golang.org/x/mod v0.17.0
	golang.org/x/net v0.33.0
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e
	google.golang.org/grpc v1.27.1
	gopkg.in/DataDog/dd-trace-go.v1 v1.19.0
	gopkg.in/fsnotify.v1 v1.4.7
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/client-go v0.19.2
	k8s.io/code-generator v0.19.2
	mvdan.cc/xurls/v2 v2.1.0
)

require (
	cloud.google.com/go v0.54.0 // indirect
	github.com/Azure/azure-sdk-for-go v32.4.0+incompatible // indirect
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Azure/go-autorest/autorest v0.9.6 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.8.2 // indirect
	github.com/Azure/go-autorest/autorest/azure/auth v0.1.0 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.1.0 // indirect
	github.com/Azure/go-autorest/autorest/date v0.2.0 // indirect
	github.com/Azure/go-autorest/autorest/to v0.2.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.1.0 // indirect
	github.com/Azure/go-autorest/logger v0.1.0 // indirect
	github.com/Azure/go-autorest/tracing v0.5.0 // indirect
	github.com/DataDog/datadog-go v2.2.0+incompatible // indirect
	github.com/Masterminds/goutils v1.1.0 // indirect
	github.com/Masterminds/semver v1.4.2 // indirect
	github.com/Masterminds/semver/v3 v3.1.0 // indirect
	github.com/Masterminds/sprig/v3 v3.1.0 // indirect
	github.com/Microsoft/go-winio v0.4.15-0.20190919025122-fc70bd9a86b5 // indirect
	github.com/Microsoft/hcsshim v0.8.7 // indirect
	github.com/OpenDNS/vegadns2client v0.0.0-20180418235048-a3fa4a771d87 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/Shopify/sarama v1.23.1 // indirect
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/akamai/AkamaiOPEN-edgegrid-golang v0.9.18 // indirect
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.458 // indirect
	github.com/armon/go-metrics v0.0.0-20190430140413-ec5e00d3c878 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/cloudflare/cloudflare-go v0.13.2 // indirect
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/containerd/containerd v1.3.2 // indirect
	github.com/containerd/continuity v0.0.0-20190426062206-aaeac12a7ffc // indirect
	github.com/coreos/etcd v3.3.13+incompatible // indirect
	github.com/cpu/goacmedns v0.0.3 // indirect
	github.com/cyphar/filepath-securejoin v0.5.1 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/dimchansky/utfbom v1.1.0 // indirect
	github.com/dnsimple/dnsimple-go v0.63.0 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.6.3 // indirect
	github.com/docker/go-metrics v0.0.0-20181218153428-b84716841b82 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/docker/libcompose v0.0.0-20190805081528-eac9fe1b8b03 // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/donovanhide/eventsource v0.0.0-20170630084216-b8f31a59085e // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/elastic/go-sysinfo v1.1.1 // indirect
	github.com/elastic/go-windows v1.0.0 // indirect
	github.com/emicklei/go-restful v2.9.5+incompatible // indirect
	github.com/evanphx/json-patch v4.9.0+incompatible // indirect
	github.com/exoscale/egoscale v0.23.0 // indirect
	github.com/felixge/httpsnoop v1.0.0 // indirect
	github.com/flynn/go-shlex v0.0.0-20150515145356-3f9db97f8568 // indirect
	github.com/go-errors/errors v1.0.1 // indirect
	github.com/go-logfmt/logfmt v0.5.0 // indirect
	github.com/go-logr/logr v0.2.0 // indirect
	github.com/go-openapi/jsonpointer v0.19.3 // indirect
	github.com/go-openapi/jsonreference v0.19.3 // indirect
	github.com/go-openapi/spec v0.19.3 // indirect
	github.com/go-openapi/swag v0.19.5 // indirect
	github.com/go-resty/resty/v2 v2.1.1-0.20191201195748-d7b97669fe48 // indirect
	github.com/gofrs/uuid v3.2.0+incompatible // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/google/uuid v1.1.1 // indirect
	github.com/googleapis/gax-go/v2 v2.0.5 // indirect
	github.com/googleapis/gnostic v0.4.1 // indirect
	github.com/gophercloud/gophercloud v0.7.0 // indirect
	github.com/gophercloud/utils v0.0.0-20200508015959-b0167b94122c // indirect
	github.com/gorilla/context v1.1.1 // indirect
	github.com/gravitational/trace v0.0.0-20190726142706-a535a178675f // indirect
	github.com/hashicorp/go-cleanhttp v0.5.1 // indirect
	github.com/hashicorp/go-immutable-radix v1.0.0 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.7 // indirect
	github.com/hashicorp/go-rootcerts v1.0.0 // indirect
	github.com/hashicorp/golang-lru v0.5.1 // indirect
	github.com/hashicorp/serf v0.8.2 // indirect
	github.com/huandu/xstrings v1.3.1 // indirect
	github.com/iij/doapi v0.0.0-20190504054126-0bbf12d6d7df // indirect
	github.com/imdario/mergo v0.3.8 // indirect
	github.com/jmespath/go-jmespath v0.3.0 // indirect
	github.com/joeshaw/multierror v0.0.0-20140124173710-69b34d4ec901 // indirect
	github.com/jonboulle/clockwork v0.1.0 // indirect
	github.com/json-iterator/go v1.1.10 // indirect
	github.com/kolo/xmlrpc v0.0.0-20200310150728-e0350524596b // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/labbsr0x/bindman-dns-webhook v1.0.2 // indirect
	github.com/labbsr0x/goh v1.0.1 // indirect
	github.com/linode/linodego v0.21.0 // indirect
	github.com/liquidweb/liquidweb-go v1.6.1 // indirect
	github.com/looplab/fsm v0.1.0 // indirect
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/mailgun/minheap v0.0.0-20170619185613-3dbe6c6bf55f // indirect
	github.com/mailgun/multibuf v0.0.0-20150714184110-565402cd71fb // indirect
	github.com/mailgun/timetools v0.0.0-20141028012446-7e6055773c51 // indirect
	github.com/mailru/easyjson v0.7.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.0 // indirect
	github.com/moby/sys/user v0.3.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/morikuni/aec v0.0.0-20170113033406-39771216ff4c // indirect
	github.com/namedotcom/go v0.0.0-20180403034216-08470befbe04 // indirect
	github.com/nrdcg/auroradns v1.0.1 // indirect
	github.com/nrdcg/desec v0.5.0 // indirect
	github.com/nrdcg/dnspod-go v0.4.0 // indirect
	github.com/nrdcg/goinwx v0.8.1 // indirect
	github.com/nrdcg/namesilo v0.2.1 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runc v1.2.8 // indirect
	github.com/opentracing-contrib/go-observer v0.0.0-20170622124052-a52f23424492 // indirect
	github.com/opentracing/basictracer-go v1.0.0 // indirect
	github.com/oracle/oci-go-sdk v24.2.0+incompatible // indirect
	github.com/ovh/go-ovh v1.1.0 // indirect
	github.com/philhofer/fwd v1.0.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pquerna/otp v1.2.0 // indirect
	github.com/prometheus/common v0.7.0 // indirect
	github.com/prometheus/procfs v0.0.8 // indirect
	github.com/rogpeppe/go-internal v1.11.0 // indirect
	github.com/sacloud/libsacloud v1.36.2 // indirect
	github.com/samuel/go-zookeeper v0.0.0-20190923202752-2cc03de413da // indirect
	github.com/santhosh-tekuri/jsonschema v1.2.4 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/tinylib/msgp v1.0.2 // indirect
	github.com/transip/gotransip/v6 v6.2.0 // indirect
	github.com/vultr/govultr v0.5.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	go.elastic.co/apm/module/apmhttp v1.7.0 // indirect
	go.elastic.co/fastjson v1.0.0 // indirect
	go.etcd.io/etcd v3.3.13+incompatible // indirect
	go.opencensus.io v0.22.3 // indirect
	go.uber.org/atomic v1.5.0 // indirect
	go.uber.org/ratelimit v0.0.0-20180316092928-c15da0234277 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b // indirect
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/term v0.27.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543 // indirect
	google.golang.org/api v0.20.0 // indirect
	google.golang.org/appengine v1.6.5 // indirect
	google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.57.0 // indirect
	gopkg.in/ns1/ns1-go.v2 v2.4.2 // indirect
	gopkg.in/redis.v5 v5.2.9 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	howett.net/plist v0.0.0-20181124034731-591f970eefbb // indirect
	k8s.io/gengo v0.0.0-20200428234225-8167cfdcfc14 // indirect
	k8s.io/klog/v2 v2.2.0 // indirect
	k8s.io/kube-openapi v0.0.0-20200805222855-6aeccd4b50c6 // indirect
	k8s.io/utils v0.0.0-20200729134348-d5654de09c73 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.0.1 // indirect
	sigs.k8s.io/yaml v1.2.0 // indirect
)

// Docker v19.03.6
replace github.com/docker/docker => github.com/docker/engine v1.4.2-0.20200204220554-5f6d6f3f2203

// Containous forks
replace (
	github.com/abbot/go-http-auth => github.com/containous/go-http-auth v0.4.1-0.20200324110947-a37a7636d23e
	github.com/go-check/check => github.com/containous/check v0.0.0-20170915194414-ca0bf163426a
	github.com/gorilla/mux => github.com/containous/mux v0.0.0-20181024131434-c33f32e26898
	github.com/mailgun/minheap => github.com/containous/minheap v0.0.0-20190809180810-6e71eb837595
	github.com/mailgun/multibuf => github.com/containous/multibuf v0.0.0-20190809014333-8b6c9a7e6bba
)
