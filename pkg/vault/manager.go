package vault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"github.com/uswitch/vault-creds/pkg/metrics"
)

type DefaultManager struct {
	client   *api.Client
	secret   Secret
	lease    time.Duration
	renew    time.Duration
	provider *VaultSecretsProvider
	template *template.Template
	gateway  *metrics.PushGateway
	outPath  string
}

func (m DefaultManager) Run(ctx context.Context, c chan int) {
	go func() {
		_, isCert := m.secret.(*Certificate)
		if isCert {
			log.Printf("renewing certificate every %s", m.renew)
		} else {
			log.Printf("renewing %s lease every %s", m.lease, m.renew)
		}

		creds, isSecret := m.secret.(*Credentials)

		renewTicks := time.Tick(m.renew)
		metricTicks := time.Tick(5 * time.Second)

		for {
			select {
			case <-ctx.Done():
				log.Infof("stopping renewal")
				return
			case <-renewTicks:
				err := m.Renew(ctx)
				if err != nil {
					if m.gateway != nil {
						m.gateway.SetFailureTime()
						m.gateway.SetFailureCount()
					}
					log.Errorf("error renewing secret: %s", err)
				} else {
					if m.gateway != nil {
						m.gateway.SetSuccessTime()
					}
				}
				if err == ErrPermissionDenied || err == ErrLeaseNotFound {
					log.Error("secret could no longer be renewed")
					c <- 1
					return
				}
				if isCert {
					err = m.Save()
					if err != nil {
						log.Errorf("error overwriting lease: %s", err)
					}
				}
				if m.gateway != nil {
					m.gateway.Push()
				}
			case <-metricTicks:
				if isSecret && m.gateway != nil {
					expireTime, err := time.Parse(time.RFC3339, *creds.LeaseExpireTime)
					if err != nil {
						log.Errorf("error parsing time: %s", err)
					}
					m.gateway.SetExpiration(expireTime.Sub(time.Now()))
					m.gateway.Push()
				}
			}
		}
	}()

}

//RevokeSelf this will attempt to revoke its own token
func (m *DefaultManager) RevokeSelf(ctx context.Context) {

	err := m.client.Auth().Token().RevokeSelf("")
	if err != nil {
		log.Errorf("failed to revoke self: %s", err)
	} else {
		log.Infof("revoked own token")
	}

}

func (m *DefaultManager) Renew(ctx context.Context) error {

	op := func() error {
		return renewAuth(m.client, int(m.lease.Seconds()))
	}

	err := backoff.Retry(op, backoff.WithContext(defaultRetryStrategy(m.lease), ctx))

	if err != nil {
		return err
	}

	creds, isCreds := m.secret.(*Credentials)
	if isCreds {
		logger := log.WithField("leaseID", creds.Secret.LeaseID)
		logger.Infof("renewing lease by %s.", m.lease)
	} else {
		logger := log.StandardLogger()
		logger.Infof("renewing certificate for %s.", m.renew)
	}

	op = func() error {
		if isCreds {
			return m.renewSecret(creds.Secret.LeaseID)
		}
		return m.renewCertificate()
	}

	err = backoff.Retry(op, backoff.WithContext(defaultRetryStrategy(m.lease), ctx))

	return err
}

func (m *DefaultManager) Save() error {
	if m.outPath != "" {
		// Ensure directory for destination file exists
		destinationDirectory := filepath.Dir(m.outPath)
		err := os.MkdirAll(destinationDirectory, 0666)
		if err != nil {
			return err
		}

		file, err := os.OpenFile(m.outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
		if err != nil {
			return err
		}
		defer file.Close()

		m.template.Execute(file, m.secret.EnvVars())

		log.Printf("wrote secrets to %s", file.Name())

		return m.secret.Save(fmt.Sprintf("%s.lease", m.outPath))
	}

	m.template.Execute(os.Stdout, m.secret.EnvVars())

	return nil
}

func (m *DefaultManager) renewSecret(leaseID string) error {
	secret, err := m.client.Sys().Renew(leaseID, int(m.lease.Seconds()))
	if err != nil || secret == nil {
		if err == nil {
			err = fmt.Errorf("secret is nil")
		}
		log.Errorf("error renewing lease: %s", err)
		fatalError := checkFatalError(err)
		if fatalError != nil {
			return backoff.Permanent(fatalError)
		}
		return err
	}
	log.WithFields(secretFields(secret)).Infof("successfully renewed secret")

	creds, _ := m.secret.(*Credentials)
	expire := time.Now().Add(time.Duration(secret.LeaseDuration) * time.Second).Format(time.RFC3339)
	creds.LeaseExpireTime = &expire

	return nil
}

func (m *DefaultManager) renewCertificate() error {
	log.Infof("renewing certificate")
	var err error
	m.secret, err = m.provider.newCertificate()
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

func renewAuth(client *api.Client, renew int) error {
	secret, err := client.Auth().Token().RenewSelf(renew)
	if err != nil || secret == nil {
		if err == nil {
			err = fmt.Errorf("secret is nil")
		}
		log.Errorf("error renewing token: %s", err)
		fatalError := checkFatalError(err)
		if fatalError != nil {
			return backoff.Permanent(fatalError)
		}
		return err
	}
	log.WithFields(secretFields(secret)).Infof("successfully renewed auth token")

	return nil
}

func NewManager(client *api.Client, secret Secret, lease time.Duration, renew time.Duration, provider *VaultSecretsProvider, template *template.Template, gateway *metrics.PushGateway, outPath string) CredentialsRenewer {

	return &DefaultManager{client: client, secret: secret, lease: lease, renew: renew, provider: provider, template: template, gateway: gateway, outPath: outPath}
}
