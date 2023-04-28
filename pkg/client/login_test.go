package client

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimpleAdminLogin(t *testing.T) {
	StartServer()
	ast := assert.New(t)
	adm, err := LoginAdminUP("root", []byte("yxcvb"), "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(adm)
}

func TestAdminRelogin(t *testing.T) {
	StartServer()
	ast := assert.New(t)
	adm, err := LoginAdminUP("root", []byte("yxcvb"), "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(adm)

	tk := adm.Token()
	rt := adm.RefreshToken()

	adm2, err := LoginAdminCli(tk, rt, "https://127.0.0.1:9543", func(tk, rt string) {
		fmt.Println("token refreshed")
	})
	ast.Nil(err)
	ast.NotNil(adm2)
}

func TestClientLogin(t *testing.T) {
	StartServer()
	ast := assert.New(t)
	cli, err := LoginClient("12345678", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)

	cli.Logout()
}
