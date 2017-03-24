package main

import (
	"context"
	vault "github.com/uswitch/vault-creds"
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"os"
	"os/signal"
	"text/template"
)

var (
	vaultAddr    = kingpin.Flag("addr", "Vault address").Default("https://localhost:8200").String()
	token        = kingpin.Flag("token", "Vault token to use in development").String()
	templateFile = kingpin.Flag("template", "Path to template file").ExistingFile()
	out          = kingpin.Flag("out", "Output file name").String()
	renew        = kingpin.Flag("renew", "Interval to renew credentials").Default("1m").Duration()
	credsPath    = kingpin.Arg("path", "Vault path to DB credentials").String()
)

func main() {
	kingpin.Parse()

	t, err := template.ParseFiles(*templateFile)
	if err != nil {
		log.Fatal("error opening template:", err)
	}

	client, err := vault.Client(*vaultAddr, *token)
	if err != nil {
		log.Fatal(err)
	}

	creds, err := vault.RequestCredentials(client, *credsPath)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		log.Println("received interrupt, releasing credentials")
		cancel()
	}()

	if *out != "" {
		file, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		t.Execute(file, creds)
		log.Printf("wrote credentials to %s", file.Name())
		go vault.Renew(ctx, client, creds, *renew)
	} else {
		t.Execute(os.Stdout, creds)
	}

	<-ctx.Done()
}
