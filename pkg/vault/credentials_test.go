package vault

import (
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestCredentials(t *testing.T) {
	f := FileCredentialsProvider{path: "/tmp/testcreds"}

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

	if creds.Secret.Data["Username"] != "Bob" || creds.Secret.Data["Password"] != "Foo" {
		t.Errorf("did not get expected credentials, got username: %v, password: %v", creds.Secret.Data["Username"], creds.Secret.Data["Password"])
	}

}
