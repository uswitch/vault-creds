package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/cenkalti/backoff"
	api "github.com/hashicorp/vault/api"
)

const (
	CredentialType  SecretType = "credential"
	CertificateType SecretType = "certificate"
)

type SecretType string

var ErrPermissionDenied = errors.New("permission denied")
var ErrLeaseNotFound = errors.New("lease not found or is not renewable")

type Secret interface {
	Save(path string) error
}

type SecretsProvider interface {
	Fetch() (Secret, error)
}

type CredentialsRenewer interface {
	Renew(ctx context.Context) error
	RevokeSelf(ctx context.Context)
	Run(ctx context.Context, c chan int)
}

type ClientFactory interface {
	Create() (*AuthClient, error)
}

func defaultRetryStrategy(max time.Duration) backoff.BackOff {
	strategy := backoff.NewExponentialBackOff()
	strategy.InitialInterval = time.Millisecond * 500
	strategy.MaxElapsedTime = max
	return strategy
}

type Credentials struct {
	Username string
	Password string
	Secret   *api.Secret
}

type Certificate struct {
	Certificate string
	PrivateKey  string
	Expiration  int64
	Secret      *api.Secret
}

type TLSConfig struct {
	CACert string
	CAPath string
}

type VaultConfig struct {
	VaultAddr string
	TLS       *TLSConfig
}

type KubernetesAuthConfig struct {
	TokenFile string
	LoginPath string
	Role      string
}

type login struct {
	JWT  string `json:"jwt"`
	Role string `json:"role"`
}

func secretFields(secret *api.Secret) log.Fields {
	fields := log.Fields{
		"requestID":     secret.RequestID,
		"leaseID":       secret.LeaseID,
		"renewable":     secret.Renewable,
		"leaseDuration": secret.LeaseDuration,
	}

	if secret.Auth != nil {
		fields["auth.policies"] = secret.Auth.Policies
		fields["auth.leaseDuration"] = secret.Auth.LeaseDuration
		fields["auth.renewable"] = secret.Auth.Renewable
		fields["warnings"] = secret.Warnings
	}

	return fields
}

func checkFatalError(err error) error {
	errorString := fmt.Sprintf("%s", err)
	if strings.Contains(errorString, "Code: 403") {
		return ErrPermissionDenied
	}
	if strings.Contains(errorString, "lease not found or lease is not renewable") {
		return ErrLeaseNotFound
	}
	return nil
}
