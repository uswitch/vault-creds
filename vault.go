package vault

import (
	"context"
	"github.com/cenkalti/backoff"
	api "github.com/hashicorp/vault/api"
	"log"
	"time"
)

type Credentials struct {
	Username string
	Password string
	secret   *api.Secret
}

func (c *Credentials) LeaseID() string {
	return c.secret.LeaseID
}

func Client(address, token string) (*api.Client, error) {
	cfg := api.DefaultConfig()
	cfg.Address = address
	cfg.ConfigureTLS(&api.TLSConfig{Insecure: true})
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	if token != "" {
		client.SetToken(token)
	}
	return client, nil
}

// token may not always be set, just for now though
func RequestCredentials(client *api.Client, path string) (*Credentials, error) {
	secret, err := client.Logical().Read(path)
	if err != nil {
		return nil, err
	}

	return &Credentials{secret.Data["username"].(string), secret.Data["password"].(string), secret}, nil
}

func renew(client *api.Client, credentials *Credentials, extension time.Duration) error {
	log.Printf("renewing lease by %s", extension)

	op := func() error {
		secret, err := client.Sys().Renew(credentials.LeaseID(), int(extension.Seconds()))
		if err != nil {
			return err
		}
		log.Printf("successfully renewed. %+v", secret)

		return nil
	}

	config := backoff.NewExponentialBackOff()
	config.InitialInterval = time.Second * 1
	config.MaxElapsedTime = extension
	err := backoff.Retry(op, config)

	if err != nil {
		log.Fatal(err)
	}

	return nil
}

func Renew(ctx context.Context, client *api.Client, credentials *Credentials, interval time.Duration) {
	log.Printf("renewing every %s", interval)
	ticks := time.Tick(interval)
	for {
		select {
		case <-ctx.Done():
			log.Println("stopping renew")
			return
		case <-ticks:
			renew(client, credentials, interval)
		}
	}
}
