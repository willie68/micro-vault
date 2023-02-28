package client

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateEncryption(t *testing.T) {
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
