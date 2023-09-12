package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	encryptMsg = "encrypt this golang"
)

func TestEnDecodeAES(t *testing.T) {
	ast := assert.New(t)
	originalText := encryptMsg
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

func TestCryptKey(t *testing.T) {
	ast := assert.New(t)

	originalText := encryptMsg

	rsk, err := generateKey()
	ast.Nil(err)

	cryptoText, err := EncryptKey(rsk.PublicKey, originalText)
	ast.Nil(err)
	ast.NotEmpty(cryptoText)

	dec, err := DecryptKey(*rsk, cryptoText)
	ast.Nil(err)
	ast.NotEmpty(dec)

	ast.Equal(originalText, dec)
}

func TestCryptPEM(t *testing.T) {
	ast := assert.New(t)

	originalText := encryptMsg

	rsk, err := generateKey()
	ast.Nil(err)

	pubpem, err := Pub2Pem(&rsk.PublicKey)
	ast.Nil(err)
	ast.NotEmpty(pubpem)

	cryptoText, err := EncryptPEM(string(pubpem), originalText)
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

	pm, err := Prv2Pem(rsk)
	ast.Nil(err)
	ast.NotEmpty(string(pm))

	rs, err := Pem2Prv(string(pm))
	ast.Nil(err)
	ast.True(rs.Equal(rsk))

	pm, err = PrvRSA2Pem(rsk)
	ast.Nil(err)
	ast.NotEmpty(string(pm))

	rs, err = Pem2Prv(string(pm))
	ast.Nil(err)
	ast.True(rs.Equal(rsk))

}

// Prv2Pem converts a private key to a PEM
func PrvRSA2Pem(rsk *rsa.PrivateKey) ([]byte, error) {
	pubbuf := x509.MarshalPKCS1PrivateKey(rsk)

	pemblock := &pem.Block{
		Type:  pemBlockRSAPrivateKey,
		Bytes: pubbuf,
	}

	return pem.EncodeToMemory(pemblock), nil
}
func TestHashSecret(t *testing.T) {
	ast := assert.New(t)

	secret := []byte("this is a secret")
	s1, err := GenerateSalt()
	ast.Nil(err)
	ast.NotNil(s1)
	ast.Equal(64, len(s1))

	h1 := HashSecret(secret, s1)
	ast.NotNil(h1)

	s2, err := GenerateSalt()
	ast.Nil(err)
	ast.NotNil(s2)
	ast.NotEqual(s1, s2)

	h2 := HashSecret(secret, s2)
	ast.NotNil(h1)
	ast.NotEqual(h1, h2)

	h3 := HashSecret(secret, s1)
	ast.Equal(h1, h3)
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
