package vault

import (
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestCredentials(t *testing.T) {
	f := FileSecretsProvider{secretType: CredentialType, path: "/tmp/testcreds"}

	secret := api.Secret{Data: map[string]interface{}{"Username": "Bob", "Password": "Foo"}}
	credentials := Credentials{Secret: &secret}
	err := credentials.Save("/tmp/testcreds")
	if err != nil {
		t.Errorf("error saving testing credentials: %v", err)
	}
	creds, err := f.Fetch()
	if err != nil {
		t.Errorf("error reading testing credentials: %v", err)
	}

	c := creds.(*Credentials)

	if c.Secret.Data["Username"] != "Bob" || c.Secret.Data["Password"] != "Foo" {
		t.Errorf("did not get expected credentials, got username: %v, password: %v", c.Secret.Data["Username"], c.Secret.Data["Password"])
	}

}
