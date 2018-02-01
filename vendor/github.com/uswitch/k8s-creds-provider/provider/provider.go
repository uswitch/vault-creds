package provider

import (
	"context"
	"time"
)

type CredentialsProvider interface {
	Fetch() (*Credentials, error)
}

type CredentialsRenewer interface {
	RenewSecret(ctx context.Context, secret *Secret, lease time.Duration) error
	RenewAuthToken(ctx context.Context, token string, lease time.Duration) error
	Run(ctx context.Context, token string, secret *Secret, lease time.Duration, renew time.Duration, errChan chan error)
}

type Credentials struct {
	Username string
	Password string
	Secret   Secret
}

type Secret interface{}
