package main

import (
	"context"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
	"text/template"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/uswitch/vault-creds/pkg/kube"
	"github.com/uswitch/vault-creds/pkg/vault"
	"gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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

	renewInterval = kingpin.Flag("renew-interval", "Interval to renew credentials").Default("15m").Duration()
	leaseDuration = kingpin.Flag("lease-duration", "Credentials lease duration").Default("1h").Duration()

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

func createClientSet(config *rest.Config) (*kubernetes.Clientset, error) {
	c, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return c, nil
}

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

	vaultConfig := &vault.VaultConfig{
		VaultAddr: *vaultAddr,
		TLS:       &vault.TLSConfig{CACert: *caCert},
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

	factory := vault.NewKubernetesAuthClientFactory(vaultConfig, kubernetesConfig)
	client, authSecret, err := factory.Create(tokenPath)
	if err != nil {
		log.Fatal("error creating client:", err)
	}

	credsProvider := vault.NewCredentialsProvider(client, *secretPath)

	var creds *vault.Credentials

	// if there's already a lease, use that and don't generate new credentials
	if leaseExist {
		log.Infof("detected existing lease")
		bytes, err := ioutil.ReadFile(leasePath)
		if err != nil {
			log.Fatal("error reading lease:", err)
		}

		err = yaml.Unmarshal(bytes, &creds)
		if err != nil {
			log.Fatal("error unmarshalling lease")
		}

	} else {
		creds, err = credsProvider.Fetch()
		if err != nil {
			log.Fatal(err)
		}
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("error creating kube client config: %s", err)
	}

	clientSet, err := createClientSet(config)
	if err != nil {
		log.Fatalf("error creating kube client: %s", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	leaseManager := vault.NewLeaseManager(client)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	go func() {
		log.Printf("renewing %s lease every %s", *leaseDuration, *renewInterval)
		renewTicks := time.Tick(*renewInterval)
		jobCompletionTicks := time.Tick(10 * time.Second)
		var status <-chan time.Time
		if *job {
			status = time.Tick(5)
		}
		for {
			select {
			case <-ctx.Done():
				log.Infof("stopping renewal")
				return
			case <-renewTicks:
				err := leaseManager.RenewAuthToken(ctx, authSecret.Auth.ClientToken, *leaseDuration)
				if err != nil {
					log.Errorf("error renewing auth: %s", err)
				}
				if err == vault.ErrPermissionDenied {
					cleanUp(leasePath, tokenPath)
					log.Fatal("auth token could no longer be renewed")
				}
				err = leaseManager.RenewSecret(ctx, creds.Secret, *leaseDuration)
				if err != nil {
					log.Errorf("error renewing db credentials: %s", err)
				}
				if err == vault.ErrPermissionDenied {
					cleanUp(leasePath, tokenPath)
					log.Fatal("credentials could no longer be renewed")
				}
			case <-status:
				status, err := kube.CheckStatus(clientSet, namespace, podName)
				if err != nil {
					log.Errorf("error getting pod status: %s", err)
				}
				if status == "Error" {
					log.Fatal("primary container has errored, shutting down")
				}
				if status == "Completed" {
					log.Infof("received completion signal")
					c <- os.Interrupt
				}
			case <-jobCompletionTicks:
				if _, err := os.Stat(*completedPath); err == nil {
					log.Infof("received completion signal")
					c <- os.Interrupt
				}
			}
		}
	}()

	if *out != "" && !leaseExist {
		file, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		t.Execute(file, creds)
		log.Printf("wrote credentials to %s", file.Name())

		//write out token
		tokenBytes, err := yaml.Marshal(authSecret)
		if err != nil {
			log.Fatal(err)
		}

		ioutil.WriteFile(tokenPath, tokenBytes, 0600)

		log.Printf("wrote token to %s", tokenPath)

		//write out full secret
		bytes, err := yaml.Marshal(creds)
		if err != nil {
			log.Fatal(err)
		}

		ioutil.WriteFile(leasePath, bytes, 0600)

		log.Printf("wrote lease to %s", leasePath)

		if *initMode {
			log.Infof("completed init")
			c <- os.Interrupt
		}
	} else if !leaseExist {
		t.Execute(os.Stdout, creds)
	}

	<-c
	if !*initMode {
		leaseManager.RevokeSelf(ctx, authSecret.Auth.ClientToken)
	}
	log.Infof("shutting down")
	cancel()
}
