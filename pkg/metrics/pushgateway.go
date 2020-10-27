package metrics

import (
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
	log "github.com/sirupsen/logrus"
)

var (
	namespace     = os.Getenv("NAMESPACE")
	podName       = os.Getenv("POD_NAME")
	promNamespace = "vault_creds"

	errorTime = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: promNamespace,
		Name:      "last_renewal_error_timestamp_seconds",
		Help:      "The timestamp of the last error during renewal of a secret",
	})

	errorCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: promNamespace,
		Name:      "error_count",
		Help:      "Number of errors when renewing credentials",
	})

	successTime = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: promNamespace,
		Name:      "last_renewal_success_timestamp_seconds",
		Help:      "The timestamp of the last successful renewal of a secret",
	})

	leaseExpiration = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: promNamespace,
		Name:      "time_until_secrets_expire",
		Help:      "The time remaining until the secret lease expires",
	})
)

type PushGateway struct {
	Pusher  *push.Pusher
	address string
}

func NewPushGateway(gatewayAddress string) *PushGateway {
	registry := prometheus.NewRegistry()
	registry.MustRegister(leaseExpiration, errorTime, successTime, errorCount)
	pusher := push.New(gatewayAddress, "vault-creds").Gatherer(registry)

	return &PushGateway{
		Pusher:  pusher,
		address: gatewayAddress,
	}

}

func (p *PushGateway) SetExpiration(newLeaseDiff time.Duration) {
	leaseExpiration.Set(float64(newLeaseDiff.Seconds()))
}

func (p *PushGateway) SetSuccessTime() {
	successTime.SetToCurrentTime()
}

func (p *PushGateway) SetFailureTime() {
	errorTime.SetToCurrentTime()
}

func (p *PushGateway) SetFailureCount() {
	errorCount.Add(1)
}

func (p *PushGateway) Push() {

	if p.address != "" {
		err := p.Pusher.
			Grouping("instance", podName).
			Grouping("namespace", namespace).
			Grouping("pod", podName).
			Add()
		if err != nil {
			log.Errorf("Could not push to Pushgateway: %s", err)
		}
	}

}
