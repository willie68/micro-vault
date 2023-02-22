package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimpleAdminLogin(t *testing.T) {
	ast := assert.New(t)
	adm, err := LoginAdmin("willie", []byte("password"))
	ast.Nil(err)
	ast.NotNil(adm)
}

func TestClientLogin(t *testing.T) {
	ast := assert.New(t)
	cli, err := LoginService("accesskey", "secret")
	ast.Nil(err)
	ast.NotNil(cli)
}
