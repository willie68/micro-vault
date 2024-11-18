package keyutils

import (
	"crypto/rsa"
	"os"

	"github.com/willie68/micro-vault/pkg/crypt"
)

func LoadPrivateKeyFromFile(f string) (*rsa.PrivateKey, error) {
	if _, err := os.Stat(f); err == nil {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		rsk, err := crypt.Pem2Prv(string(b))
		if err != nil {
			return nil, err
		}
		return rsk, nil
	}
	return nil, nil
}

func SavePrivateKeyToFile(f string, rsk *rsa.PrivateKey) error {
	if f != "" {
		b, err := crypt.Prv2Pem(rsk)
		if err != nil {
			return err
		}

		err = os.WriteFile(f, b, os.ModePerm)
		if err != nil {
			return err
		}
	}
	return nil
}
