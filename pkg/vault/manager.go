package vault

import (
	"context"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/vault/api"
)

type DefaultLeaseManager struct {
	client *api.Client
	secret *api.Secret
	lease  time.Duration
	renew  time.Duration
}

func (m DefaultLeaseManager) Run(ctx context.Context, c chan int) {
	go func() {

		log.Printf("renewing %s lease every %s", m.lease, m.renew)

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

	logger := log.WithField("leaseID", m.secret.LeaseID)
	logger.Infof("renewing lease by %s.", m.lease)

	op = func() error {
		return renewSecret(m.client, m.secret.LeaseID, int(m.lease.Seconds()))
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

func NewLeaseManager(client *api.Client, secret *api.Secret, lease time.Duration, renew time.Duration) CredentialsRenewer {
	return &DefaultLeaseManager{
		client: client,
		secret: secret,
		lease:  lease,
		renew:  renew,
	}
}
