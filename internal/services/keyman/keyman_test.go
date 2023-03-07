package keyman

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"testing"

	"github.com/samber/do"
	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/config"
)

const (
	keyfile1 = "../../../testdata/private1.pem"
	keyfile2 = "../../../testdata/private2.pem"
)

func TestNewKeyman(t *testing.T) {
	ast := assert.New(t)

	err := os.Remove(keyfile1)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		panic(err)
	}

	cfg := config.Config{
		Service: config.Service{
			PrivateKey: keyfile1,
		},
	}
	cfg.Provide()

	k, err := NewKeyman()
	ast.Nil(err)
	ast.NotNil(k)

	k1 := do.MustInvokeNamed[Keyman](nil, DoKeyman)
	ast.NotNil(k1)

	pr := k.PrivateKey()
	ast.NotNil(pr)

	pb := k.PrivateKey()
	ast.NotNil(pb)
	do.ShutdownNamed(nil, config.DoServiceConfig)
	do.ShutdownNamed(nil, DoKeyman)
}

func TestKeymanPEM(t *testing.T) {
	ast := assert.New(t)

	rsk, err := rsa.GenerateKey(rand.Reader, 2048)
	ast.Nil(err)
	err = os.Remove(keyfile2)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		panic(err)
	}
	err = saveToFile(keyfile2, rsk)
	ast.Nil(err)

	cfg := config.Config{
		Service: config.Service{
			PrivateKey: keyfile2,
		},
	}
	cfg.Provide()

	k, err := NewKeyman()
	ast.Nil(err)
	ast.NotNil(k)

	pr := k.PrivateKey()
	ast.NotNil(pr)

	do.ShutdownNamed(nil, config.DoServiceConfig)
	do.ShutdownNamed(nil, DoKeyman)
}
