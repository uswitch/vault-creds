package vault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	log "github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
	yaml "gopkg.in/yaml.v1"
)

// KubernetesVaultClientFactory creates a Vault client
// authenticated against a kubernetes service account
// token
type KubernetesVaultClientFactory struct {
	vault *VaultConfig
	kube  *KubernetesAuthConfig
}

type FileVaultClientFactory struct {
	vault *VaultConfig
	path  string
}

type AuthClient struct {
	Client *api.Client
	secret *api.Secret
}

// Create returns a Vault client that has been authenticated
// with the service account token. It can be used to make other
// Vault requests
func (f *KubernetesVaultClientFactory) Create() (*AuthClient, error) {
	client, err := createUnauthenticatedClient(f.vault)
	if err != nil {
		return nil, err
	}

	var secret *api.Secret
	secret, err = f.authenticate(client)
	if err != nil {
		return nil, err
	}

	return &AuthClient{Client: client, secret: secret}, nil
}

func createUnauthenticatedClient(v *VaultConfig) (*api.Client, error) {
	cfg := api.DefaultConfig()
	cfg.Address = v.VaultAddr
	cfg.ConfigureTLS(&api.TLSConfig{CACert: v.TLS.CACert})
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (f *FileVaultClientFactory) Create() (*AuthClient, error) {
	client, err := createUnauthenticatedClient(f.vault)
	if err != nil {
		return nil, err
	}

	var secret *api.Secret
	log.Info("detected existing vault token, using that")
	bytes, err := ioutil.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("error reading token:%v", err)
	}

	err = yaml.Unmarshal(bytes, &secret)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling token: %v", err)
	}

	client.SetToken(secret.Auth.ClientToken)
	return &AuthClient{Client: client, secret: secret}, nil
}

// Exchanges the kubernetes service account token for a vault token
func (f *KubernetesVaultClientFactory) authenticate(client *api.Client) (*api.Secret, error) {
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

func NewKubernetesAuthClientFactory(vault *VaultConfig, kube *KubernetesAuthConfig) ClientFactory {
	return &KubernetesVaultClientFactory{vault: vault, kube: kube}
}

func NewFileAuthClientFactory(vault *VaultConfig, path string) ClientFactory {
	return &FileVaultClientFactory{vault: vault, path: path}
}

func (a *AuthClient) Save(path string) error {
	//write out token
	tokenBytes, err := yaml.Marshal(a.secret)
	if err != nil {
		return fmt.Errorf("error marshalling auth secret: %v", err)
	}

	err = ioutil.WriteFile(path, tokenBytes, 0600)
	if err != nil {
		return fmt.Errorf("error writing auth secret to file: %v", err)
	}

	log.Infof("wrote token to %s", path)

	return nil
}
