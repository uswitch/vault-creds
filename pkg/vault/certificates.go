package vault

import (
	"fmt"
	"io/ioutil"

	log "github.com/Sirupsen/logrus"
	yaml "gopkg.in/yaml.v1"
)

func unmarshalCertificate(bytes []byte) (*Certificate, error) {
	var cert Certificate
	err := yaml.Unmarshal(bytes, &cert)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling lease: %v", err)
	}
	return &cert, nil
}

func (c *Certificate) Save(path string) error {
	//write out full secret
	bytes, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("error marshalling cert: %v", err)
	}

	err = ioutil.WriteFile(path, bytes, 0600)
	if err != nil {
		return fmt.Errorf("error writing cert to file: %v", err)
	}

	log.Printf("wrote lease to %s", path)
	return nil
}
