package keyman

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"testing"

	"github.com/samber/do"
	"github.com/stretchr/testify/assert"
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

	k, err := NewKeyman(keyfile1)
	ast.Nil(err)
	ast.NotNil(k)

	k1 := do.MustInvoke[Keyman](nil)
	ast.NotNil(k1)

	pr := k.PrivateKey()
	ast.NotNil(pr)

	pb := k.PrivateKey()
	ast.NotNil(pb)

	err = do.Shutdown[Keyman](nil)
	ast.Nil(err)
}

func TestKeymanPEM(t *testing.T) {
	ast := assert.New(t)

	rsk, err := rsa.GenerateKey(rand.Reader, 4096)
	ast.Nil(err)
	err = os.Remove(keyfile2)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		panic(err)
	}
	err = saveToFile(keyfile2, rsk)
	ast.Nil(err)

	k, err := NewKeyman(keyfile2)
	ast.Nil(err)
	ast.NotNil(k)

	pr := k.PrivateKey()
	ast.NotNil(pr)

	err = do.Shutdown[Keyman](nil)
	ast.Nil(err)
}
