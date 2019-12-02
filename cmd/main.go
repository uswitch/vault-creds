package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"

	log "github.com/Sirupsen/logrus"
	"github.com/uswitch/vault-creds/pkg/kube"
	"github.com/uswitch/vault-creds/pkg/vault"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	vaultAddr           = kingpin.Flag("vault-addr", "Vault address, e.g. https://vault:8200").String()
	serviceAccountToken = kingpin.Flag("token-file", "Service account token path").Default("/var/run/secrets/kubernetes.io/serviceaccount/token").String()
	loginPath           = kingpin.Flag("login-path", "Vault path to authenticate against").Required().String()
	authRole            = kingpin.Flag("auth-role", "Kubernetes authentication role").Required().String()
	secretPath          = kingpin.Flag("secret-path", "Path to secret in Vault. eg. database/creds/foo").Required().String()
	caCert              = kingpin.Flag("ca-cert", "Path to CA certificate/certificate folder to validate Vault server").String()

	templateFile = kingpin.Flag("template", "Path to template file").ExistingFile()
	out          = kingpin.Flag("out", "Output file name").String()

	renewInterval = kingpin.Flag("renew-interval", "Interval to renew credentials").Default("15m").Duration()
	leaseDuration = kingpin.Flag("lease-duration", "Credentials lease duration").Default("1h").Duration()

	getCertificate   = kingpin.Flag("get-certificate", "Whether to fetch certificates or not").Default("false").Bool()
	commonName = kingpin.Flag("common-name", "Commonname used for certificates").String()
	ttl        = kingpin.Flag("ttl", "TTL for certificate").String()

	jsonOutput = kingpin.Flag("json-log", "Output log in JSON format").Default("false").Bool()

	completedPath = kingpin.Flag("completed-path", "Path where a 'completion' file will be dropped").Default("/tmp/vault-creds/completed").String()
	job           = kingpin.Flag("job", "Whether to run in cronjob mode").Default("false").Bool()
	initMode      = kingpin.Flag("init", "write out credentials but do not renew").Default("false").Bool()
)

var (
	namespace  = os.Getenv("NAMESPACE")
	podName    = os.Getenv("POD_NAME")
	leaseExist = false
)

var (
	SHA = ""
)

//This removes the lease and token files in the event of them being expired
func cleanUp(leasePath, tokenPath string) {
	log.Infof("deleting lease and credentials")

	err := os.Remove(leasePath)
	if err != nil {
		log.Errorf("failed to remove lease: %s", err)
	}

	err = os.Remove(tokenPath)
	if err != nil {
		log.Errorf("failed to remove token: %s", err)
	}
}

func appendEnvVars(secret vault.Secret) map[string]string {
	envMap := make(map[string]string)

	for _, v := range os.Environ() {
		splitEnv := strings.Split(v, "=")
		envMap[splitEnv[0]] = splitEnv[1]
	}

	switch s := secret.(type) {
	case *vault.Credentials:
		// overwrites env variables called Username and Password
		envMap["Username"] = s.Username
		envMap["Password"] = s.Password
	case *vault.Certificate:
		envMap["Certificate"] = s.Certificate
		envMap["PrivateKey"] = s.PrivateKey
	}

	return envMap
}

func main() {
	kingpin.Parse()

	if *jsonOutput {
		log.SetFormatter(&log.JSONFormatter{})
	}

	logger := log.WithFields(log.Fields{"gitSHA": SHA})
	logger.Infof("started application")

	t, err := template.ParseFiles(*templateFile)
	if err != nil {
		log.Fatal("error opening template:", err)
	}

	var vaultTLS vault.TLSConfig

	if *caCert != "" {
		fi, err := os.Stat(*caCert)
		if err != nil {
			log.Fatal(err)
		}
		if fi.Mode().IsDir() {
			vaultTLS.CAPath = *caCert
		} else {
			vaultTLS.CACert = *caCert
		}
	}

	var secretType vault.SecretType

	options := make(map[string]string, 0)

	if *getCertificate && *commonName == "" {
		log.Fatal("error: must supply common name when requesting certificate")
	} else if *getCertificate {
		secretType = vault.CertificateType

		options["common_name"] = *commonName
		options["ttl"] = *ttl
	} else {
		secretType = vault.CredentialType
	}

	vaultConfig := &vault.VaultConfig{
		VaultAddr: *vaultAddr,
		TLS:       &vaultTLS,
	}
	kubernetesConfig := &vault.KubernetesAuthConfig{
		TokenFile: *serviceAccountToken,
		LoginPath: *loginPath,
		Role:      *authRole,
	}

	leasePath := *out + ".lease"
	tokenPath := *out + ".token"
	if _, err = os.Stat(leasePath); err == nil {
		leaseExist = true
	}

	if leaseExist && *initMode {
		cleanUp(leasePath, tokenPath)
		log.Fatal("lease detected while in init mode, shutting down and cleaning up")
	}

	var factory vault.ClientFactory
	if leaseExist {
		factory = vault.NewFileAuthClientFactory(vaultConfig, tokenPath)
	} else {
		factory = vault.NewKubernetesAuthClientFactory(vaultConfig, kubernetesConfig)
	}

	authClient, err := factory.Create()
	if err != nil {
		log.Fatal("error creating client:", err)
	}

	var secretsProvider vault.SecretsProvider

	// if there's already a lease, use that and don't generate new credentials
	if leaseExist {
		secretsProvider = vault.NewFileSecretsProvider(secretType, leasePath, options)
	} else {
		secretsProvider = vault.NewVaultSecretsProvider(authClient.Client, secretType, *secretPath, options)
	}

	secret, err := secretsProvider.Fetch()
	if err != nil {
		log.Fatalf("failed to retrieve secret: %v", err)
	}

	leaseManager := vault.NewLeaseManager(authClient.Client, secret, *leaseDuration, *renewInterval, *secretPath, options)

	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	errChan := make(chan int)

	go leaseManager.Run(ctx, errChan)

	if *job {
		checker, err := kube.NewKubeChecker(podName, namespace)
		if err != nil {
			log.Fatal(err)
		}
		go checker.Run(ctx, errChan)
	}

	go func() {
		for {
			select {
			case errVal := <-errChan:
				if errVal == 1 { //something wrong with the lease/token
					cleanUp(leasePath, tokenPath)
					log.Fatal("fatal error shutting down")
				} else if errVal == 2 { //something wrong with another container
					log.Fatal("shutting down")
				} else if errVal == 0 { //other container's have finished
					c <- os.Interrupt
				}
			}
		}
	}()

	if *out != "" && !leaseExist {
		// Ensure directory for destination file exists
		destinationDirectory := filepath.Dir(*out)
		err := os.MkdirAll(destinationDirectory, 0666)
		if err != nil {
			log.Fatal(err)
		}

		file, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		t.Execute(file, appendEnvVars(secret))
		log.Printf("wrote secrets to %s", file.Name())

		err = authClient.Save(tokenPath)
		if err != nil {
			cleanUp(leasePath, tokenPath)
			log.Fatal(err)
		}

		err = secret.Save(leasePath)
		if err != nil {
			cleanUp(leasePath, tokenPath)
			log.Fatal(err)
		}

		if *initMode {
			log.Infof("completed init")
			c <- os.Interrupt
		}
	} else if !leaseExist {
		t.Execute(os.Stdout, appendEnvVars(secret))
	}

	<-c
	if !*initMode {
		leaseManager.RevokeSelf(ctx)
		cleanUp(leasePath, tokenPath)
	}
	log.Infof("shutting down")
	cancel()

}
