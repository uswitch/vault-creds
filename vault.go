package vault

import (
	"context"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/cenkalti/backoff"
	api "github.com/hashicorp/vault/api"
	"io/ioutil"
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

type TLSConfig struct {
	CACert     string
	ServerName string
}

type vaultToken struct {
	token string
}

type login struct {
	JWT  string `json:"jwt"`
	Role string `json:"role"`
}

type authResponse struct {
}

// Exchanges the kubernetes service account token for a vault token
func Authenticate(client *api.Client, tokenPath, loginPath, role string) error {
	bytes, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("error reading token: %s", err)
	}

	req := client.NewRequest("POST", fmt.Sprintf("/v1/auth/%s", loginPath))
	req.SetJSONBody(&login{JWT: string(bytes), Role: role})
	resp, err := client.RawRequest(req)
	if err != nil {
		return err
	}

	if resp.Error() != nil {
		return resp.Error()
	}

	var secret api.Secret
	err = json.NewDecoder(resp.Body).Decode(&secret)
	if err != nil {
		return fmt.Errorf("error parsing response: %s", err)
	}

	log.WithField("policies", secret.Auth.Policies).Infof("authenticated")

	client.SetToken(secret.Auth.ClientToken)
	return nil
}

func Client(address string, tls *TLSConfig) (*api.Client, error) {
	cfg := api.DefaultConfig()
	cfg.Address = address
	cfg.ConfigureTLS(&api.TLSConfig{CACert: tls.CACert, TLSServerName: tls.ServerName})
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
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

// TODO
// change extension to be calculated as when the new credentials should expire- which
// would always be now + horizon (e.g. now + 1hr)
func renew(client *api.Client, credentials *Credentials, extension time.Duration) error {
	logger := log.WithField("leaseID", credentials.LeaseID())

	logger.Infof("renewing lease by %s.", extension)

	op := func() error {
		_, err := client.Sys().Renew(credentials.LeaseID(), int(extension.Seconds()))
		if err != nil {
			logger.Errorf("error renewing lease: %s", err)
			return err
		}
		logger.Infof("successfully renewed")

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

func Renew(ctx context.Context, client *api.Client, credentials *Credentials, interval, lease time.Duration) {
	log.Printf("renewing %s lease every %s", lease, interval)
	ticks := time.Tick(interval)
	for {
		select {
		case <-ctx.Done():
			log.Infof("stopping renewal")
			return
		case <-ticks:
			renew(client, credentials, lease)
		}
	}
}
