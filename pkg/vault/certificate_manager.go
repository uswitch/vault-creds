package vault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/vault/api"
)

type DefaultCertificateManager struct {
	client      *api.Client
	Certificate *Certificate
	lease       time.Duration
	renew       time.Duration
	provider    *VaultSecretsProvider
	template    *template.Template
	outPath     string
}

func (m DefaultCertificateManager) Run(ctx context.Context, c chan int) {
	go func() {
		log.Printf("renewing certificate every %s", m.renew)

		renewTicks := time.Tick(m.renew)

		for {
			select {
			case <-ctx.Done():
				log.Infof("stopping renewal")
				return
			case <-renewTicks:
				err := m.Renew(ctx)
				if err != nil {
					log.Errorf("error renewing secret: %s", err)
				}
				if err == ErrPermissionDenied || err == ErrLeaseNotFound {
					log.Error("secret could no longer be renewed")
					c <- 1
					return
				}
				err = m.save()
				if err != nil {
					log.Errorf("error overwriting lease: %s", err)
				}
			}
		}
	}()

}

func (m *DefaultCertificateManager) Renew(ctx context.Context) error {

	op := func() error {
		return renewAuth(m.client, int(m.lease.Seconds()))
	}

	err := backoff.Retry(op, backoff.WithContext(defaultRetryStrategy(m.lease), ctx))

	if err != nil {
		return err
	}

	op = func() error {
		logger := log.StandardLogger()
		logger.Infof("renewing certificate for %s.", m.renew)
		return m.renewCert()
	}

	err = backoff.Retry(op, backoff.WithContext(defaultRetryStrategy(m.lease), ctx))

	return err
}

func (m *DefaultCertificateManager) EnvVars() map[string]string {
	envMap := make(map[string]string)

	for _, v := range os.Environ() {
		splitEnv := strings.Split(v, "=")
		envMap[splitEnv[0]] = splitEnv[1]
	}

	envMap["Certificate"] = m.Certificate.Certificate
	envMap["PrivateKey"] = m.Certificate.PrivateKey

	return envMap
}

func (m *DefaultCertificateManager) RevokeSelf(ctx context.Context) {

	err := m.client.Auth().Token().RevokeSelf("")
	if err != nil {
		log.Errorf("failed to revoke self: %s", err)
	} else {
		log.Infof("revoked own token")
	}

}

func (m *DefaultCertificateManager) renewCert() error {
	log.Infof("renewing certificate")
	var err error
	m.Certificate, err = m.provider.newCertificate()
	if err != nil {
		log.Errorf("error renewing certificate: %s", err)
		fatalError := checkFatalError(err)
		if fatalError != nil {
			return backoff.Permanent(fatalError)
		}
		return err
	}

	return nil
}

func (m *DefaultCertificateManager) save() error {
	if m.outPath != "" {
		// Ensure directory for destination file exists
		destinationDirectory := filepath.Dir(m.outPath)
		err := os.MkdirAll(destinationDirectory, 0666)
		if err != nil {
			log.Fatal(err)
		}

		file, err := os.OpenFile(m.outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		m.template.Execute(file, m.EnvVars())

		log.Printf("wrote secrets to %s", file.Name())
		return m.Certificate.Save(fmt.Sprintf("%s.lease", m.outPath))
	} else {
		m.template.Execute(os.Stdout, m.EnvVars())
	}
	return nil
}

func NewCertificateManager(client *api.Client, certificate *Certificate, lease time.Duration, provider *VaultSecretsProvider, template *template.Template, outPath string) CredentialsRenewer {
	renew := time.Until(time.Unix(certificate.Expiration, 0)).Round(time.Minute)

	return &DefaultCertificateManager{client: client, Certificate: certificate, lease: lease, renew: renew, provider: provider, template: template, outPath: outPath}
}
