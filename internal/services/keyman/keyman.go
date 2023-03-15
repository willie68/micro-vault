package keyman

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"os"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/pkg/crypt"
)

// manage the server side main key, used for encryption/signature

// DoKeyman the key for dependency injection
const DoKeyman = "keyman"

// Keyman the key manager service
type Keyman struct {
	cfg config.Config
	rsk *rsa.PrivateKey
	kid string
}

// NewKeyman creates a new Keyman service
func NewKeyman() (*Keyman, error) {
	k := Keyman{
		cfg: do.MustInvokeNamed[config.Config](nil, config.DoServiceConfig),
	}

	err := k.Init()
	if err != nil {
		return nil, err
	}
	do.ProvideNamedValue[Keyman](nil, DoKeyman, k)
	return &k, nil
}

// Init initialize the key manager
func (k *Keyman) Init() error {
	var rsk *rsa.PrivateKey
	var err error
	if k.cfg.Service.PrivateKey != "" {
		rsk, err = loadFromFile(k.cfg.Service.PrivateKey)
		if err != nil {
			return err
		}
	}
	if rsk == nil {
		rsk, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			logging.Logger.Errorf("failed to generate private key: %s", err)
			return err
		}
		err = saveToFile(k.cfg.Service.PrivateKey, rsk)
		if err != nil {
			return err
		}
	}
	k.rsk = rsk

	key, err := jwk.New(rsk)

	err = jwk.AssignKeyID(key)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return err
	}
	k.kid = key.KeyID()

	return nil
}

// PrivateKey getting the private key for this service
func (k *Keyman) PrivateKey() *rsa.PrivateKey {
	return k.rsk
}

// PublicKey return the public key for checking the signature of a token
func (k *Keyman) PublicKey() rsa.PublicKey {
	return k.rsk.PublicKey
}

// KID getting the kid
func (k *Keyman) KID() string {
	return k.kid
}

func loadFromFile(f string) (*rsa.PrivateKey, error) {
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

func saveToFile(f string, rsk *rsa.PrivateKey) error {
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
