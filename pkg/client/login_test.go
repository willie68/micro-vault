package client

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/config"
)

var (
	srvStarted bool
)

func StartServer() {
	fmt.Println("starting server")
	// loading the config file
	config.File = "../../testdata/service_local.yaml"
	err := config.Load()
	if err != nil {
		panic("can't load local config")
	}
}

func TestSimpleAdminLogin(t *testing.T) {
	StartServer()
	ast := assert.New(t)
	adm, err := LoginAdminUP("root", []byte("yxcvb"), "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(adm)
}

func TestAdminRelogin(t *testing.T) {
	ast := assert.New(t)
	adm, err := LoginAdminUP("root", []byte("yxcvb"), "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(adm)

	tk := adm.Token()

	adm2, err := LoginAdminToken(tk, "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(adm2)
}

func TestClientLogin(t *testing.T) {
	ast := assert.New(t)
	cli, err := LoginService("12345678", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)

	cli.Logout()
}
