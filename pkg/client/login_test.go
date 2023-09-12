package client

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	localServer = "https://127.0.0.1:9543"
	rootuser    = "root"
	rootpwd     = "yxcvb"
	access      = "12345678"
	secret      = "e7d767cd1432145820669be6a60a912e"
)

func TestSimpleAdminLogin(t *testing.T) {
	StartServer()
	ast := assert.New(t)
	adm, err := LoginAdminUP(rootuser, []byte(rootpwd), localServer)
	ast.Nil(err)
	ast.NotNil(adm)

	adm.Logout()
}

func TestAdminRelogin(t *testing.T) {
	StartServer()
	ast := assert.New(t)
	adm, err := LoginAdminUP(rootuser, []byte(rootpwd), localServer)
	ast.Nil(err)
	ast.NotNil(adm)

	tk := adm.Token()
	rt := adm.RefreshToken()

	adm2, err := LoginAdminCli(tk, rt, localServer, func(tk, rt string) {
		fmt.Println("token refreshed")
	})
	ast.Nil(err)
	ast.NotNil(adm2)

	adm.Logout()
}

func TestClientLogin(t *testing.T) {
	StartServer()

	ast := assert.New(t)
	cli, err := LoginClient(access, secret, localServer)
	ast.Nil(err)
	ast.NotNil(cli)

	cli.Logout()
}

func TestClientRelogin(t *testing.T) {
	StartServer()

	ast := assert.New(t)

	cli, err := LoginClient(access, secret, localServer)
	ast.Nil(err)
	ast.NotNil(cli)

	cli2, err := LoginClientCli(cli.token, cli.refreshToken, localServer, func(tk, rt string) {
		t.Log("refresh done")
	})
	ast.Nil(err)
	ast.NotNil(cli)

	cli.Logout()

	cli2.Logout()
}

func TestClientBuilder(t *testing.T) {
	StartServer()

	ast := assert.New(t)

	cli, err := NewClient().WithBaseURL(localServer).WithAccessKey(access).WithSecret(secret).Login()
	ast.Nil(err)
	ast.NotNil(cli)

	cli.Logout()
}

func TestAdminBuilder(t *testing.T) {
	StartServer()

	ast := assert.New(t)

	adm, err := NewAdmin().WithBaseURL(localServer).WithUser(rootuser).WithPassword([]byte(rootpwd)).Login()
	ast.Nil(err)
	ast.NotNil(adm)
	adm.Logout()
}
