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
				err := m.RenewAuthToken(ctx)
				if err != nil {
					log.Errorf("error renewing auth: %s", err)
				}
				if err == ErrPermissionDenied || err == ErrLeaseNotFound {
					//	cleanUp(leasePath, tokenPath)
					log.Error("auth token could no longer be renewed")
					c <- 1
					return
				}
				err = m.RenewSecret(ctx)
				if err != nil {
					log.Errorf("error renewing db credentials: %s", err)
				}
				if err == ErrPermissionDenied || err == ErrLeaseNotFound {
					//cleanUp(leasePath, tokenPath)
					log.Error("credentials could no longer be renewed")
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

func (m *DefaultLeaseManager) RenewSecret(ctx context.Context) error {
	logger := log.WithField("leaseID", m.secret.LeaseID)
	logger.Infof("renewing lease by %s.", m.lease)

	op := func() error {
		secret, err := m.client.Sys().Renew(m.secret.LeaseID, int(m.lease.Seconds()))
		if err != nil {
			logger.Errorf("error renewing lease: %s", err)
			fatalError := checkFatalError(err)
			if fatalError != nil {
				return backoff.Permanent(fatalError)
			}
			return err
		}
		logger.WithFields(secretFields(secret)).Infof("successfully renewed secret")

		return nil
	}

	err := backoff.Retry(op, backoff.WithContext(defaultRetryStrategy(m.lease), ctx))

	return err
}

func NewLeaseManager(client *api.Client, secret *api.Secret, lease time.Duration, renew time.Duration) CredentialsRenewer {
	return &DefaultLeaseManager{
		client: client,
		secret: secret,
		lease:  lease,
		renew:  renew,
	}
}

func (m *DefaultLeaseManager) RenewAuthToken(ctx context.Context) error {
	op := func() error {
		secret, err := m.client.Auth().Token().RenewSelf(int(m.lease.Seconds()))
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

	err := backoff.Retry(op, backoff.WithContext(defaultRetryStrategy(m.lease), ctx))

	return err
}
