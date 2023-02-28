package crypt

import (
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
