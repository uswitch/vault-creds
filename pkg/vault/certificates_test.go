package vault

import (
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestCertificate(t *testing.T) {
	f := FileSecretsProvider{secretType: CertificateType, path: "/tmp/testcert"}
	secret := api.Secret{Data: map[string]interface{}{
		"Certificate": "-----BEGIN CERTIFICATE-----R4ND0M5TR1NG-----END CERTIFICATE-----",
		"PrivateKey":  "-----BEGIN PRIVATE KEY-----PR1V4T3K3Y-----END PRIVATE KEY-----",
		"Expiration":  123456789,
	}}
	certificate := Certificate{Secret: &secret}
	err := certificate.Save("/tmp/testcert")
	if err != nil {
		t.Errorf("error saving testing credentials: %v", err)
	}
	cert, err := f.Fetch()
	if err != nil {
		t.Errorf("error reading testing credentials: %v", err)
	}

	c := cert.(*Certificate)

	if c.Secret.Data["Certificate"] != "-----BEGIN CERTIFICATE-----R4ND0M5TR1NG-----END CERTIFICATE-----" || c.Secret.Data["PrivateKey"] != "-----BEGIN PRIVATE KEY-----PR1V4T3K3Y-----END PRIVATE KEY-----" || c.Secret.Data["Expiration"] != 123456789 {
		t.Errorf("did not get expected credentials, got certificate: %v, privatekey: %v, expiration: %v", c.Secret.Data["Certificate"], c.Secret.Data["PrivateKey"], c.Secret.Data["Expiration"])
	}

}
