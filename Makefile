bin/vault-creds: $(shell find . -name '*.go')
	go build -o bin/vaultcreds cmd/*.go