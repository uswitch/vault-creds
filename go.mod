module github.com/uswitch/vault-creds

go 1.15

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/prometheus/client_golang v1.8.0
	github.com/sirupsen/logrus v1.7.0
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/yaml.v1 v1.0.0-20140924161607-9f9df34309c0
	k8s.io/api v0.19.3
	k8s.io/apimachinery v0.19.3
	k8s.io/client-go v0.19.3
	k8s.io/utils v0.0.0-20201015054608-420da100c033 // indirect
)
