package main

import (
	vault "github.com/uswitch/vault-creds"
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"os"
	"text/template"
)

var (
	vaultAddr    = kingpin.Flag("addr", "Vault address").Default("https://localhost:8200").String()
	token        = kingpin.Flag("token", "Vault token to use in development").String()
	templateFile = kingpin.Flag("template", "Path to template file").ExistingFile()
	out          = kingpin.Flag("out", "Output file name").String()
	credsPath    = kingpin.Arg("path", "Vault path to DB credentials").String()
)

func main() {
	kingpin.Parse()

	t, err := template.ParseFiles(*templateFile)
	if err != nil {
		log.Fatal("error opening template:", err)
	}

	creds, err := vault.RequestCredentials(*vaultAddr, *credsPath, *token)
	if err != nil {
		log.Fatal(err)
	}

	if *out != "" {
		file, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		t.Execute(file, creds)
	} else {
		t.Execute(os.Stdout, creds)
	}
}
