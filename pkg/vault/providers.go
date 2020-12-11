package vault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	log "github.com/sirupsen/logrus"
)

type VaultSecretsProvider struct {
	client     *api.Client
	path       string
	secretType SecretType
	options    map[string]string
}

type FileSecretsProvider struct {
	path       string
	secretType SecretType
	options    map[string]string
}

func NewVaultSecretsProvider(client *api.Client, secretType SecretType, secretPath string, options map[string]string) SecretsProvider {
	return &VaultSecretsProvider{client: client, secretType: secretType, options: options, path: secretPath}
}

func NewFileSecretsProvider(secretType SecretType, path string, options map[string]string) SecretsProvider {
	return &FileSecretsProvider{secretType: secretType, path: path, options: options}
}

func (c *VaultSecretsProvider) Fetch() (Secret, error) {
	log.Infof("requesting %v", c.secretType)

	if c.secretType == CertificateType {
		return c.newCertificate()
	}

	return c.newCredentials()
}

func (c *VaultSecretsProvider) newCertificate() (*Certificate, error) {
	params := make(map[string]interface{}, 0)
	for k, v := range c.options {
		params[k] = interface{}(v)
	}

	secret, err := c.client.Logical().Write(c.path, params)
	if err != nil || secret == nil {
		if err == nil {
			return nil, fmt.Errorf("secret is nil")
		}
		return nil, err
	}

	exp, err := secret.Data["expiration"].(json.Number).Int64()
	if err != nil {
		return nil, err
	}

	parsedBundle, err := certutil.ParsePKIMap(secret.Data)
	if err != nil {
		return nil, err
	}

	bundle, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, err
	}

	return &Certificate{Certificate: bundle.Certificate, PrivateKey: bundle.PrivateKey, Expiration: exp, Secret: secret}, nil
}

func (c *VaultSecretsProvider) newCredentials() (*Credentials, error) {
	secret, err := c.client.Logical().Read(c.path)
	if err != nil || secret == nil {
		if err == nil {
			return nil, fmt.Errorf("secret is nil")
		}
		return nil, err
	}

	leaseExpireTime := time.Now().Add(time.Duration(secret.LeaseDuration) * time.Second).Format(time.RFC3339)

	return &Credentials{
		Username:        secret.Data["username"].(string),
		Password:        secret.Data["password"].(string),
		Secret:          secret,
		LeaseExpireTime: &leaseExpireTime,
	}, nil
}

func (c *FileSecretsProvider) Fetch() (Secret, error) {
	log.Infof("detected existing lease")
	bytes, err := ioutil.ReadFile(c.path)
	if err != nil {
		return nil, fmt.Errorf("error reading lease: %v", err)
	}

	if c.secretType == CertificateType {
		return unmarshalCertificate(bytes)
	}

	return unmarshalCredentials(bytes)
}
