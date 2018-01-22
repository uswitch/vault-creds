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

type CredentialsProvider interface {
	Fetch() (*Credentials, error)
}

type CredentialsRenewer interface {
	Renew(ctx context.Context, creds *Credentials, lease time.Duration) error
}

type DefaultLeaseManager struct {
	clientFactory ClientFactory
}

func (m *DefaultLeaseManager) client() (*api.Client, error) {
	return m.clientFactory.Create()
}

func (m *DefaultLeaseManager) Renew(ctx context.Context, credentials *Credentials, lease time.Duration) error {
	client, err := m.client()
	if err != nil {
		return err
	}

	logger := log.WithField("leaseID", credentials.LeaseID())
	logger.Infof("renewing lease by %s.", lease)

	op := func() error {
		_, err := client.Sys().Renew(credentials.LeaseID(), int(lease.Seconds()))
		if err != nil {
			logger.Errorf("error renewing lease: %s", err)
			return err
		}
		logger.Infof("successfully renewed")

		return nil
	}

	config := backoff.NewExponentialBackOff()
	config.InitialInterval = time.Second * 1
	config.MaxElapsedTime = lease
	err = backoff.Retry(op, config)

	return err
}

func NewLeaseManager(factory ClientFactory) CredentialsRenewer {
	return &DefaultLeaseManager{clientFactory: factory}
}

type ClientFactory interface {
	Create() (*api.Client, error)
}

type DefaultCredentialsProvider struct {
	factory ClientFactory
	path    string
}

func NewCredentialsProvider(factory ClientFactory, secretPath string) *DefaultCredentialsProvider {
	return &DefaultCredentialsProvider{factory: factory, path: secretPath}
}

func (c *DefaultCredentialsProvider) Fetch() (*Credentials, error) {
	log.Infof("requesting credentials")
	client, err := c.client()
	if err != nil {
		return nil, err
	}

	secret, err := client.Logical().Read(c.path)
	if err != nil {
		return nil, err
	}

	return &Credentials{secret.Data["username"].(string), secret.Data["password"].(string), secret}, nil
}

func (c *DefaultCredentialsProvider) client() (*api.Client, error) {
	return c.factory.Create()
}

type Credentials struct {
	Username string
	Password string
	secret   *api.Secret
}

func (c *Credentials) LeaseID() string {
	return c.secret.LeaseID
}

type TLSConfig struct {
	CACert string
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

// DefaultVaultClientFactory creates a Vault client
// authenticated against a kubernetes service account
// token
type DefaultVaultClientFactory struct {
	vault *VaultConfig
	kube  *KubernetesAuthConfig
}

// Create returns a Vault client that has been authenticated
// with the service account token. It can be used to make other
// Vault requests
func (f *DefaultVaultClientFactory) Create() (*api.Client, error) {
	client, err := f.createUnauthenticatedClient()
	if err != nil {
		return nil, err
	}

	err = f.authenticate(client)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (f *DefaultVaultClientFactory) createUnauthenticatedClient() (*api.Client, error) {
	cfg := api.DefaultConfig()
	cfg.Address = f.vault.VaultAddr
	cfg.ConfigureTLS(&api.TLSConfig{CACert: f.vault.TLS.CACert})
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	return client, nil
}

type login struct {
	JWT  string `json:"jwt"`
	Role string `json:"role"`
}

// Exchanges the kubernetes service account token for a vault token
func (f *DefaultVaultClientFactory) authenticate(client *api.Client) error {
	bytes, err := ioutil.ReadFile(f.kube.TokenFile)
	if err != nil {
		return fmt.Errorf("error reading token: %s", err)
	}

	req := client.NewRequest("POST", fmt.Sprintf("/v1/auth/%s", f.kube.LoginPath))
	req.SetJSONBody(&login{JWT: string(bytes), Role: f.kube.Role})
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

func NewKubernetesAuthClientFactory(vault *VaultConfig, kube *KubernetesAuthConfig) *DefaultVaultClientFactory {
	return &DefaultVaultClientFactory{vault: vault, kube: kube}
}
