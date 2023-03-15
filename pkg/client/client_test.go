package client

import (
	"encoding/json"
	"os"
	"testing"

	"log"

	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/pkg/pmodel"
)

func init() {
	ad, err := LoginAdminUP("root", []byte("yxcvb"), "https://127.0.0.1:9543")
	if err != nil {
		panic(err)
	}
	adm = ad
	pb, err := os.ReadFile("../../testdata/playbook.json")
	if err != nil {
		panic(err)
	}
	err = adm.SendPlaybook(string(pb))
	if err != nil {
		log.Printf("error in playbook: %v", err)
	}
}

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
	t.Logf("signature: %v", sig)

	// Check locally
	ok, err := cli2.SignCheck("tester1", sig.Signature, orgtxt)
	ast.Nil(err)
	ast.True(ok)

	// Check message on server side
	ok, err = cli2.SignCheckSS("tester1", *sig)
	ast.Nil(err)
	ast.True(ok)

	ok, err = cli2.SignCheck("tester2", sig.Signature, orgtxt)
	ast.NotNil(err)
	ast.False(ok)
}

func TestServerSideCryptGroup(t *testing.T) {
	ast := assert.New(t)
	adr := struct {
		Lastname  string `json:"lastname"`
		Firstname string `json:"firstname"`
	}{
		Lastname:  "Klaas",
		Firstname: "Wilfried",
	}

	b, err := json.Marshal(adr)
	ast.Nil(err)
	ast.NotNil(b)

	msg := pmodel.Message{
		Type:      "group",
		Recipient: "group2",
		Decrypt:   false,
		Message:   string(b),
	}

	cli, err := LoginService("12345678", "yxcvb", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)
	defer cli.Logout()

	cli2, err := LoginService("87654321", "yxcvb", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli2)
	defer cli2.Logout()

	m, err := cli.CryptSS(msg)
	ast.Nil(err)
	ast.NotNil(m)
	ast.NotEmpty(m.ID)
	ast.True(len(m.Message) > 0)

	m2, err := cli2.CryptSS(*m)
	ast.Nil(err)
	ast.NotEmpty(m2)
	ast.NotEmpty(m.ID)
	ast.True(len(m.Message) > 0)
	adr2 := struct {
		Lastname  string `json:"lastname"`
		Firstname string `json:"firstname"`
	}{}
	err = json.Unmarshal([]byte(m2.Message), &adr2)
	ast.Nil(err)

	ast.Equal(adr.Firstname, adr2.Firstname)
	ast.Equal(adr.Lastname, adr2.Lastname)
}

func TestNameToken(t *testing.T) {
	ast := assert.New(t)
	cli, err := LoginService("12345678", "yxcvb", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)
	defer cli.Logout()

	ast.NotEmpty(cli.Token())
	ast.Equal("tester1", cli.Name())
	ast.NotNil(cli.privatekey)
}
