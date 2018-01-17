package main

import (
	"context"
	log "github.com/Sirupsen/logrus"
	vault "github.com/uswitch/vault-creds"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"os/signal"
	"text/template"
)

var (
	vaultAddr           = kingpin.Flag("vault-addr", "Vault address, e.g. https://vault:8200").String()
	serviceAccountToken = kingpin.Flag("token-file", "Service account token path").Default("/var/run/secrets/kubernetes.io/serviceaccount/token").String()
	loginPath           = kingpin.Flag("login-path", "Vault path to authenticate against").Required().String()
	authRole            = kingpin.Flag("auth-role", "Kubernetes authentication role").Required().String()
	secretPath          = kingpin.Flag("secret-path", "Path to secret in Vault. eg. database/creds/foo").Required().String()
	caCert              = kingpin.Flag("ca-cert", "Path to CA certificate to validate Vault server").String()

	templateFile = kingpin.Flag("template", "Path to template file").ExistingFile()
	out          = kingpin.Flag("out", "Output file name").String()

	renew         = kingpin.Flag("renew", "Interval to renew credentials").Default("1m").Duration()
	leaseDuration = kingpin.Flag("lease-duration", "Credentials lease duration").Default("1h").Duration()
)

func main() {
	kingpin.Parse()

	t, err := template.ParseFiles(*templateFile)
	if err != nil {
		log.Fatal("error opening template:", err)
	}

	client, err := vault.Client(*vaultAddr, &vault.TLSConfig{CACert: *caCert})
	if err != nil {
		log.Fatal(err)
	}
	err = vault.Authenticate(client, *serviceAccountToken, *loginPath, *authRole)
	if err != nil {
		log.Fatal(err)
	}

	creds, err := vault.RequestCredentials(client, *secretPath)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	if *out != "" {
		file, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		t.Execute(file, creds)
		log.Printf("wrote credentials to %s", file.Name())
	} else {
		t.Execute(os.Stdout, creds)
	}

	go vault.Renew(ctx, client, creds, *renew, *leaseDuration)

	<-c
	log.Infof("shutting down")
	cancel()
}
