package vault

import (
	"fmt"
	"io/ioutil"

	log "github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
	yaml "gopkg.in/yaml.v1"
)

type VaultCredentialsProvider struct {
	client *api.Client
	path   string
}

type FileCredentialsProvider struct {
	path string
}

func NewVaultCredentialsProvider(client *api.Client, secretPath string) CredentialsProvider {
	return &VaultCredentialsProvider{client: client, path: secretPath}
}

func NewFileCredentialsProvider(path string) CredentialsProvider {
	return &FileCredentialsProvider{path: path}
}

func (c *VaultCredentialsProvider) Fetch() (*Credentials, error) {
	log.Infof("requesting credentials")
	secret, err := c.client.Logical().Read(c.path)
	if err != nil {
		return nil, err
	}

	log.WithFields(secretFields(secret)).Infof("succesfully retrieved credentials")

	return &Credentials{secret.Data["username"].(string), secret.Data["password"].(string), secret}, nil
}

func (c *FileCredentialsProvider) Fetch() (*Credentials, error) {

	var creds Credentials
	log.Infof("detected existing lease")
	bytes, err := ioutil.ReadFile(c.path)
	if err != nil {
		return nil, fmt.Errorf("error reading lease: %v", err)
	}

	err = yaml.Unmarshal(bytes, &creds)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling lease: %v", err)
	}

	return &creds, nil
}

func (c *Credentials) Save(path string) error {
	//write out full secret
	bytes, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("error marshalling creds: %v", err)
	}

	err = ioutil.WriteFile(path, bytes, 0600)
	if err != nil {
		return fmt.Errorf("error writing creds to file: %v", err)
	}

	log.Printf("wrote lease to %s", path)
	return nil
}
