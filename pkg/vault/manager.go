package vault

import (
	"context"
	"fmt"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/vault/api"
)

type DefaultLeaseManager struct {
	client  *api.Client
	secret  Secret
	lease   time.Duration
	renew   time.Duration
	path    string
	options map[string]string
}

func (m DefaultLeaseManager) Run(ctx context.Context, c chan int) {
	go func() {
		if _, ok := m.secret.(*Certificate); ok {
			log.Printf("renewing certificate every %s", m.renew)
		} else {
			log.Printf("renewing %s lease every %s", m.lease, m.renew)
		}

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
			}
		}
	}()

}

//RevokeSelf this will attempt to revoke its own token
func (m *DefaultLeaseManager) RevokeSelf(ctx context.Context) {

	err := m.client.Auth().Token().RevokeSelf("")
	if err != nil {
		log.Errorf("failed to revoke self: %s", err)
	} else {
		log.Infof("revoked own token")
	}

}

func (m *DefaultLeaseManager) Renew(ctx context.Context) error {

	op := func() error {
		return renewAuth(m.client, int(m.lease.Seconds()))
	}

	err := backoff.Retry(op, backoff.WithContext(defaultRetryStrategy(m.lease), ctx))

	if err != nil {
		return err
	}

	op = func() error {
		switch s := m.secret.(type) {
		case *Credentials:
			logger := log.WithField("leaseID", s.Secret.LeaseID)
			logger.Infof("renewing lease by %s.", m.lease)

			return renewSecret(m.client, s.Secret.LeaseID, int(m.lease.Seconds()))
		case *Certificate:
			logger := log.StandardLogger()
			logger.Infof("renewing certificate for %s.", m.options["ttl"])

			return renewCert(m.client, m.path, m.options)
		default:
			return fmt.Errorf("could not dertemine secret type")
		}
	}

	err = backoff.Retry(op, backoff.WithContext(defaultRetryStrategy(m.lease), ctx))

	return err
}

func renewAuth(client *api.Client, renew int) error {
	secret, err := client.Auth().Token().RenewSelf(renew)
	if err != nil {
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

func renewSecret(client *api.Client, leaseID string, renew int) error {
	secret, err := client.Sys().Renew(leaseID, renew)
	if err != nil {
		log.Errorf("error renewing lease: %s", err)
		fatalError := checkFatalError(err)
		if fatalError != nil {
			return backoff.Permanent(fatalError)
		}
		return err
	}
	log.WithFields(secretFields(secret)).Infof("successfully renewed secret")

	return nil
}

func renewCert(client *api.Client, path string, options map[string]string) error {
	log.Infof("renewing certificate")

	params := make(map[string]interface{}, 0)
	for k, v := range options {
		params[k] = interface{}(v)
	}

	secret, err := client.Logical().Write(path, params)
	if err != nil {
		log.Errorf("error renewing lease: %s", err)
		fatalError := checkFatalError(err)
		if fatalError != nil {
			return backoff.Permanent(fatalError)
		}
		return err
	}

	log.WithFields(secretFields(secret)).Infof("succesfully renewed cert")

	return nil
}

func NewLeaseManager(client *api.Client, secret Secret, lease time.Duration, renew time.Duration, path string, options map[string]string) CredentialsRenewer {
	if s, ok := secret.(*Certificate); ok {
		renew = time.Until(time.Unix(s.Expiration, 0)).Round(time.Minute)
	}

	return &DefaultLeaseManager{
		client:  client,
		secret:  secret,
		lease:   lease,
		renew:   renew,
		path:    path,
		options: options,
	}
}
