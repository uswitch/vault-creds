package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/cenkalti/backoff"
	"github.com/hashicorp/vault/api"
	"github.com/uswitch/k8s-creds-provider/provider"
)

type VaultCredentialsRenewer struct {
	client *api.Client
}

func NewLeaseManager(client *api.Client) provider.CredentialsRenewer {
	return &VaultCredentialsRenewer{client: client}
}

func defaultRetryStrategy(max time.Duration) backoff.BackOff {
	strategy := backoff.NewExponentialBackOff()
	strategy.InitialInterval = time.Millisecond * 500
	strategy.MaxElapsedTime = max
	return strategy
}

func (m *VaultCredentialsRenewer) RenewAuthToken(ctx context.Context, token string, lease time.Duration) error {
	op := func() error {
		secret, err := m.client.Auth().Token().RenewSelf(int(lease.Seconds()))
		if err != nil {
			return err
		}
		log.WithFields(secretFields(secret)).Infof("successfully renewed auth token")

		return nil
	}

	err := backoff.Retry(op, backoff.WithContext(defaultRetryStrategy(lease), ctx))

	return err
}

func (m *VaultCredentialsRenewer) RenewSecret(ctx context.Context, secret *provider.Secret, lease time.Duration) error {
	vaultSecret := (*secret).(*api.Secret)
	logger := log.WithField("leaseID", vaultSecret.LeaseID)
	logger.Infof("renewing lease by %s.", lease)

	op := func() error {
		secret, err := m.client.Sys().Renew(vaultSecret.LeaseID, int(lease.Seconds()))
		if err != nil {
			return err
		}
		logger.WithFields(secretFields(secret)).Infof("successfully renewed secret")

		return nil
	}

	err := backoff.Retry(op, backoff.WithContext(defaultRetryStrategy(lease), ctx))

	return err
}

func (m *VaultCredentialsRenewer) Run(ctx context.Context, token string, secret *provider.Secret, lease time.Duration, renew time.Duration, errChan chan error) {
	log.Printf("renewing %s lease every %s", lease, renew)
	ticks := time.Tick(renew)
	for {
		select {
		case <-ctx.Done():
			log.Infof("stopping renewal")
			return
		case <-ticks:
			err := m.RenewAuthToken(ctx, token, lease)
			if err != nil {
				errChan <- err
				break
			}
			err = m.RenewSecret(ctx, secret, lease)
			errChan <- err
		}
	}
}

type VaultCredentialsProvider struct {
	client *api.Client
	path   string
}

func NewCredentialsProvider(client *api.Client, secretPath string) *VaultCredentialsProvider {
	return &VaultCredentialsProvider{client: client, path: secretPath}
}

func (c *VaultCredentialsProvider) Fetch() (*provider.Credentials, error) {
	log.Infof("requesting credentials")
	secret, err := c.client.Logical().Read(c.path)
	if err != nil {
		return nil, err
	}
	log.WithFields(secretFields(secret)).Infof("succesfully retrieved credentials")

	return &provider.Credentials{secret.Data["username"].(string), secret.Data["password"].(string), secret}, nil
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

// VaultClientFactory creates a Vault client
// authenticated against a kubernetes service account
// token
type VaultClientFactory struct {
	vault *VaultConfig
	kube  *KubernetesAuthConfig
}

func NewKubernetesAuthClientFactory(vault *VaultConfig, kube *KubernetesAuthConfig) *VaultClientFactory {
	return &VaultClientFactory{vault: vault, kube: kube}
}

// Create returns a Vault client that has been authenticated
// with the service account token. It can be used to make other
// Vault requests
func (f *VaultClientFactory) Create() (*api.Client, *api.Secret, error) {
	client, err := f.createUnauthenticatedClient()
	if err != nil {
		return nil, nil, err
	}

	secret, err := f.authenticate(client)
	if err != nil {
		return nil, nil, err
	}

	return client, secret, nil
}

func (f *VaultClientFactory) createUnauthenticatedClient() (*api.Client, error) {
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
func (f *VaultClientFactory) authenticate(client *api.Client) (*api.Secret, error) {
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
