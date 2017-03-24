package vault

import (
	api "github.com/hashicorp/vault/api"
)

type Credentials struct {
	Username string
	Password string
	secret   *api.Secret
}

// token may not always be set, just for now though
func RequestCredentials(vaultAddr, path string, token string) (*Credentials, error) {
	cfg := api.DefaultConfig()
	cfg.Address = vaultAddr
	cfg.ConfigureTLS(&api.TLSConfig{Insecure: true})
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	if token != "" {
		client.SetToken(token)
	}

	secret, err := client.Logical().Read(path)
	if err != nil {
		return nil, err
	}

	return &Credentials{secret.Data["username"].(string), secret.Data["password"].(string), secret}, nil
}
