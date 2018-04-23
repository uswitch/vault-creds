package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/cenkalti/backoff"
	api "github.com/hashicorp/vault/api"
	yaml "gopkg.in/yaml.v1"
)

type CredentialsProvider interface {
	Fetch() (*Credentials, error)
}

type CredentialsRenewer interface {
	RenewSecret(ctx context.Context, secret *api.Secret, lease time.Duration) error
	RenewAuthToken(ctx context.Context, token string, lease time.Duration) error
	RevokeSelf(ctx context.Context, token string)
}

type ClientFactory interface {
	Create() (*api.Client, *api.Secret, error)
}

type DefaultLeaseManager struct {
	client *api.Client
}

func defaultRetryStrategy(max time.Duration) backoff.BackOff {
	strategy := backoff.NewExponentialBackOff()
	strategy.InitialInterval = time.Millisecond * 500
	strategy.MaxElapsedTime = max
	return strategy
}

func (m *DefaultLeaseManager) RenewAuthToken(ctx context.Context, token string, lease time.Duration) error {
	op := func() error {
		secret, err := m.client.Auth().Token().RenewSelf(int(lease.Seconds()))
		if err != nil {
			log.Errorf("error renewing token: %s", err)
			return err
		}
		log.WithFields(secretFields(secret)).Infof("successfully renewed auth token")

		return nil
	}

	err := backoff.Retry(op, backoff.WithContext(defaultRetryStrategy(lease), ctx))

	return err
}

//RevokeSelf this will attempt to revoke it's own token
func (m *DefaultLeaseManager) RevokeSelf(ctx context.Context, token string) {

	err := m.client.Auth().Token().RevokeSelf(token)
	if err != nil {
		log.Errorf("failed to revoke self: %s", err)
	} else {
		log.Infof("revoked own token")
	}

}

func (m *DefaultLeaseManager) RenewSecret(ctx context.Context, secret *api.Secret, lease time.Duration) error {
	logger := log.WithField("leaseID", secret.LeaseID)
	logger.Infof("renewing lease by %s.", lease)

	op := func() error {
		secret, err := m.client.Sys().Renew(secret.LeaseID, int(lease.Seconds()))
		if err != nil {
			logger.Errorf("error renewing lease: %s", err)
			return err
		}
		logger.WithFields(secretFields(secret)).Infof("successfully renewed secret")

		return nil
	}

	err := backoff.Retry(op, backoff.WithContext(defaultRetryStrategy(lease), ctx))

	return err
}

func NewLeaseManager(client *api.Client) CredentialsRenewer {
	return &DefaultLeaseManager{client: client}
}

type DefaultCredentialsProvider struct {
	client *api.Client
	path   string
}

func NewCredentialsProvider(client *api.Client, secretPath string) *DefaultCredentialsProvider {
	return &DefaultCredentialsProvider{client: client, path: secretPath}
}

func (c *DefaultCredentialsProvider) Fetch() (*Credentials, error) {
	log.Infof("requesting credentials")
	secret, err := c.client.Logical().Read(c.path)
	if err != nil {
		return nil, err
	}

	log.WithFields(secretFields(secret)).Infof("succesfully retrieved credentials")

	return &Credentials{secret.Data["username"].(string), secret.Data["password"].(string), secret}, nil
}

type Credentials struct {
	Username string
	Password string
	Secret   *api.Secret
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
func (f *DefaultVaultClientFactory) Create(tokenPath string) (*api.Client, *api.Secret, error) {
	client, err := f.createUnauthenticatedClient()
	if err != nil {
		return nil, nil, err
	}

	var secret *api.Secret

	//If the token file exists read that instead of generating a new auth token
	if _, err = os.Stat(tokenPath); err == nil {
		log.Info("detected existing vault token, using that")
		secret, err = f.authRead(client, tokenPath)
		if err != nil {
			return nil, nil, err
		}
	} else {
		secret, err = f.authenticate(client)
		if err != nil {
			return nil, nil, err
		}
	}

	return client, secret, nil
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

// Exchanges the kubernetes service account token for a vault token
func (f *DefaultVaultClientFactory) authenticate(client *api.Client) (*api.Secret, error) {
	bytes, err := ioutil.ReadFile(f.kube.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("error reading token: %s", err)
	}

	req := client.NewRequest("POST", fmt.Sprintf("/v1/auth/%s", f.kube.LoginPath))
	req.SetJSONBody(&login{JWT: string(bytes), Role: f.kube.Role})
	resp, err := client.RawRequest(req)
	if err != nil {
		return nil, err
	}

	if resp.Error() != nil {
		return nil, resp.Error()
	}

	var secret api.Secret
	err = json.NewDecoder(resp.Body).Decode(&secret)
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %s", err)
	}

	logger := log.WithFields(secretFields(&secret))
	logger.Infof("successfully authenticated")
	client.SetToken(secret.Auth.ClientToken)

	return &secret, nil
}

func (f *DefaultVaultClientFactory) authRead(client *api.Client, tokenPath string) (*api.Secret, error) {

	var secret api.Secret

	bytes, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		log.Fatal("error reading token:", err)
	}

	err = yaml.Unmarshal(bytes, &secret)
	if err != nil {
		log.Fatal("error unmarshalling token")
	}

	client.SetToken(secret.Auth.ClientToken)

	return &secret, nil
}

func NewKubernetesAuthClientFactory(vault *VaultConfig, kube *KubernetesAuthConfig) *DefaultVaultClientFactory {
	return &DefaultVaultClientFactory{vault: vault, kube: kube}
}
