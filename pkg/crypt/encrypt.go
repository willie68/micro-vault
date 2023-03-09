package crypt

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// Encrypt string to base64 crypto using AES
func Encrypt(key []byte, text string) (string, error) {
	// key := []byte(keyText)
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt from base64 to decrypted string
func Decrypt(key []byte, cryptoText string) (string, error) {
	ciphertext, _ := base64.StdEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext), nil
}

// EncryptPEM string to base64 crypto using PEM File with public key
func EncryptPEM(key string, text string) (string, error) {
	pub, err := Pem2pub(key)
	if err != nil {
		return "", err
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte(text), nil)

	if err != nil {
		return "", err
	}
	// convert to base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptKey decrypting a message with a private key
func DecryptKey(pk rsa.PrivateKey, dt string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(dt)
	if err != nil {
		return "", err
	}
	db, err := pk.Decrypt(nil, b, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return "", err
	}
	return string(db), nil
}

// Sign singing a data part with a private key
func Sign(pk rsa.PrivateKey, dt string) (string, error) {
	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHashSum, err := hashme(dt)
	if err != nil {
		return "", err
	}

	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	signature, err := rsa.SignPSS(rand.Reader, &pk, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// SignCheckPEM check a signature of a data string
func SignCheckPEM(key string, signature, dt string) (bool, error) {
	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHashSum, err := hashme(dt)
	if err != nil {
		return false, err
	}

	pub, err := Pem2pub(key)
	if err != nil {
		return false, err
	}

	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPSS(pub, crypto.SHA256, msgHashSum, sig, nil)
	if err != nil {
		return false, err
	}
	return true, nil
}

func Pem2pub(key string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("error getting public key")
	}

	p, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := p.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not a rsa public key")
	}
	return pub, nil
}

// Pem2Prv converts a pem string into a rsa private key
func Pem2Prv(key string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("error getting public key")
	}

	p, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	prv, ok := p.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not a rsa private key")
	}
	return prv, nil
}

// Prv2PEM converts a private key to a PEM
func Prv2PEM(rsk *rsa.PrivateKey) ([]byte, error) {
	pubbuf, err := x509.MarshalPKCS8PrivateKey(rsk)
	if err != nil {
		return []byte{}, err
	}

	pemblock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pubbuf,
	}

	return pem.EncodeToMemory(pemblock), nil
}

func hashme(dt string) ([]byte, error) {
	msg := []byte(dt)
	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err := msgHash.Write(msg)
	if err != nil {
		return []byte{}, err
	}
	return msgHash.Sum(nil), nil
}
