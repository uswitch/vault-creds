package vault

import (
	"golang.org/x/exp/maps"
	"os"
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

func TestEnvVars(t *testing.T) {
	c := Credentials{
		Username: "user",
		Password: "passwd",
	}
	input := map[string]string{
		"DB_URL":             "http://localhost:9001",
		"DB_URL_PARAMS":      "http://localhost:9001?sslmode=force",
		"DB_URL_MORE_PARAMS": "http://localhost:9001?sslmode=force&param1=val1&par2=something",
	}
	expected_output := map[string]string{
		"Username": c.Username,
		"Password": c.Password,
	}

	maps.Copy(expected_output, input)
	os.Clearenv()
	for k, v := range input {
		defer os.Unsetenv(k)
		err := os.Setenv(k, v)
		if err != nil {
			t.Error(err)
		}
	}

	result := c.EnvVars()

	if !maps.Equal(expected_output, result) {
		t.Errorf("Result: %v is not equalt to expected result: %v", result, expected_output)
	}

}
