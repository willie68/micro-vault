package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnDecodeAES(t *testing.T) {
	ast := assert.New(t)
	originalText := "encrypt this golang"
	t.Logf("org: %s", originalText)
	key := []byte("example key 1234")

	// encrypt value to base64
	cryptoText, err := Encrypt(key, originalText)
	ast.Nil(err)
	ast.NotEmpty(cryptoText)
	t.Logf("crypt: %s", cryptoText)

	// encrypt base64 crypto to original value
	text, err := Decrypt(key, cryptoText)
	ast.Nil(err)
	ast.Equal(originalText, text)
	t.Logf("dec: %s", text)
}

func TestCryptPEM(t *testing.T) {
	ast := assert.New(t)

	originalText := "encrypt this golang"

	rsk, err := generateKey()
	ast.Nil(err)

	pem, err := Pub2Pem(&rsk.PublicKey)
	ast.Nil(err)
	ast.NotEmpty(pem)

	cryptoText, err := EncryptPEM(string(pem), originalText)
	ast.Nil(err)
	ast.NotEmpty(cryptoText)

	dec, err := DecryptKey(*rsk, cryptoText)
	ast.Nil(err)
	ast.NotEmpty(dec)

	ast.Equal(originalText, dec)
}

func TestSign(t *testing.T) {
	ast := assert.New(t)

	rsk, err := generateKey()
	ast.Nil(err)

	dt := "Dies sit die Message"

	sig, err := Sign(*rsk, dt)
	ast.Nil(err)
	ast.NotEmpty(sig)

	pub := rsk.PublicKey
	ok, err := SignCheck(&pub, sig, dt)
	ast.Nil(err)
	ast.True(ok)

	pem, err := Pub2Pem(&pub)
	ast.Nil(err)

	ok, err = SignCheckPEM(string(pem), sig, dt)
	ast.Nil(err)
	ast.True(ok)
}

func TestKID(t *testing.T) {
	ast := assert.New(t)

	rsk, err := generateKey()
	ast.Nil(err)

	kid, err := GetKID(rsk)
	ast.Nil(err)
	ast.NotEmpty(kid)

	pem, err := Prv2Pem(rsk)
	ast.Nil(err)
	ast.NotEmpty(string(pem))

	kid2, err := GetKIDOfPEM(string(pem))
	ast.Nil(err)
	ast.Equal(kid, kid2)
}

func TestPEM(t *testing.T) {
	ast := assert.New(t)

	rsk, err := generateKey()
	ast.Nil(err)

	pem, err := Prv2Pem(rsk)
	ast.Nil(err)
	ast.NotEmpty(string(pem))

	rs, err := Pem2Prv(string(pem))
	ast.Nil(err)
	ast.True(rs.Equal(rsk))
}

func generateKey() (*rsa.PrivateKey, error) {
	token := make([]byte, 16)
	_, err := rand.Read(token)
	if err != nil {
		return nil, err
	}
	rsk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return rsk, nil
}
