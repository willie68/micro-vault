package client

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptSameUser(t *testing.T) {
	ast := assert.New(t)
	cli, err := LoginService("12345678", "yxcvb", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)

	defer cli.Logout()

	dt := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		Username: "Willie",
		Password: "sehrGeheim",
	}

	js, err := json.Marshal(dt)
	ast.Nil(err)
	orgtxt := string(js)

	b, id, err := cli.Encrypt4Group("group1", orgtxt)
	ast.Nil(err)
	ast.NotNil(js)
	ast.NotEmpty(id)
	ast.True(len(b) > 0)
	t.Logf("id: %s \r\ndata: %s", id, b)

	text, err := cli.Decrypt4Group(id, b)
	ast.Nil(err)
	ast.NotEmpty(text)
	ast.Equal(orgtxt, text)
	t.Logf("text: %s", text)
}

func TestEncryptGroup4(t *testing.T) {
	ast := assert.New(t)
	cli, err := LoginService("12345678", "yxcvb", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)
	defer cli.Logout()

	cli2, err := LoginService("87654321", "yxcvb", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli2)
	defer cli2.Logout()

	dt := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		Username: "Willie",
		Password: "sehrGeheim",
	}

	js, err := json.Marshal(dt)
	ast.Nil(err)
	orgtxt := string(js)

	b, id, err := cli.Encrypt4Group("group4", orgtxt)
	ast.Nil(err)
	ast.NotNil(js)
	ast.NotEmpty(id)
	ast.True(len(b) > 0)
	t.Logf("id: %s \r\ndata: %s", id, b)

	text, err := cli2.Decrypt4Group(id, b)
	ast.Nil(err)
	ast.NotEmpty(text)
	ast.Equal(orgtxt, text)
	t.Logf("text: %s", text)
}

func TestEncryptClient(t *testing.T) {
	ast := assert.New(t)
	cli, err := LoginService("12345678", "yxcvb", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)
	defer cli.Logout()

	cli2, err := LoginService("87654321", "yxcvb", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli2)
	defer cli2.Logout()

	dt := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		Username: "Willie",
		Password: "sehrGeheim",
	}

	js, err := json.Marshal(dt)
	ast.Nil(err)
	ast.NotNil(js)
	orgtxt := string(js)

	b, err := cli.Encrypt4Client("tester2", orgtxt)
	ast.Nil(err)
	ast.NotEmpty(b)
	t.Logf("data: %s", b)

	text, err := cli2.Decrypt4Client(b)
	ast.Nil(err)
	ast.NotEmpty(text)
	ast.Equal(orgtxt, text)
	t.Logf("text: %s", text)
}

func TestSigning(t *testing.T) {
	ast := assert.New(t)
	cli, err := LoginService("12345678", "yxcvb", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)
	defer cli.Logout()

	cli2, err := LoginService("87654321", "yxcvb", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli2)
	defer cli2.Logout()

	dt := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		Username: "Willie",
		Password: "sehrGeheim",
	}

	js, err := json.Marshal(dt)
	ast.Nil(err)
	ast.NotNil(js)
	orgtxt := string(js)

	sig, err := cli.Sign(orgtxt)
	ast.Nil(err)
	ast.NotEmpty(sig)
	t.Logf("signature: %s", sig)

	ok, err := cli2.SignCheck("tester1", sig, orgtxt)
	ast.Nil(err)
	ast.True(ok)

	ok, err = cli2.SignCheck("tester2", sig, orgtxt)
	ast.NotNil(err)
	ast.False(ok)
}
