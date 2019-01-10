package vault

import (
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestAuthTokenRead(t *testing.T) {
	path := "/tmp/testToken"
	authClient := AuthClient{secret: &api.Secret{Auth: &api.SecretAuth{ClientToken: "foo"}}}
	err := authClient.Save("/tmp/testToken")
	if err != nil {
		t.Errorf("error saving testing credentials: %v", err)
	}

	factory := FileVaultClientFactory{path: path, vault: &VaultConfig{TLS: &TLSConfig{CACert: "foo"}}}
	auth, err := factory.Create()
	if err != nil {
		t.Errorf("error creating authFactory: %v", err)
	}

	if auth.Client.Token() != "foo" {
		t.Errorf("token should be foo got: %v", auth.Client.Token())
	}
}
