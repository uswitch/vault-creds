package vault

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v1"
)

func unmarshalCredentials(bytes []byte) (*Credentials, error) {
	var creds Credentials
	err := yaml.Unmarshal(bytes, &creds)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling lease: %v", err)
	}
	return &creds, nil
}

func (c *Credentials) Save(path string) error {
	//write out full secret
	bytes, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("error marshalling creds: %v", err)
	}

	err = ioutil.WriteFile(path, bytes, 0600)
	if err != nil {
		return fmt.Errorf("error writing creds to file: %v", err)
	}

	log.Printf("wrote lease to %s", path)
	return nil
}

func (c *Credentials) EnvVars() map[string]string {
	envMap := make(map[string]string)

	for _, v := range os.Environ() {
		splitEnv := strings.Split(v, "=")
		envMap[splitEnv[0]] = strings.Join(splitEnv[1:], "=")
	}

	// overwrites env variables called Username and Password
	envMap["Username"] = c.Username
	envMap["Password"] = c.Password

	return envMap
}
