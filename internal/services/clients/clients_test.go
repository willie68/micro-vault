package clients

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/internal/services/keyman"
	"github.com/willie68/micro-vault/internal/services/playbook"
	"github.com/willie68/micro-vault/internal/services/storage"
	cry "github.com/willie68/micro-vault/pkg/crypt"
	"github.com/willie68/micro-vault/pkg/pmodel"
)

var (
	stg interfaces.Storage
	cls Clients
)

func init() {
	var err error
	stg, err = storage.NewMemory()
	if err != nil {
		panic(1)
	}
	pb := playbook.NewPlaybookFile("../../../testdata/playbook.json")
	err = pb.Load()
	if err != nil {
		panic(1)
	}
	err = pb.Play()
	if err != nil {
		panic(1)
	}
	c := config.Config{
		Service: config.Service{
			Rootuser:   "root",
			Rootpwd:    "yxcvb",
			PrivateKey: "../../../testdata/private.pem",
		},
	}
	c.Provide()
	_, err = keyman.NewKeyman()
	if err != nil {
		panic(1)
	}

	cls, err = NewClients()
	if err != nil {
		panic(1)
	}
}

func TestClientLogin(t *testing.T) {
	ast := assert.New(t)
	tk, rt, k, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)
	ast.NotEmpty(k)
	ast.NotEmpty(rt)
	ast.NotEmpty(tk)

	checkToken(tk, ast)
	checkRToken(rt, ast)
}

func TestRefresh(t *testing.T) {
	ast := assert.New(t)
	tk, rt, k, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)
	ast.NotEmpty(k)
	ast.NotEmpty(rt)
	ast.NotEmpty(tk)

	checkToken(tk, ast)
	checkRToken(rt, ast)

	tk2, rt2, err := cls.Refresh(rt)
	ast.Nil(err)

	ast.NotEmpty(tk2)
	ast.NotEmpty(rt2)

	checkToken(tk2, ast)
	checkRToken(rt2, ast)

	_, err = cls.checkRtk(rt)
	ast.NotNil(err)

	tk3, rt3, err := cls.Refresh(rt)
	ast.NotNil(err)
	ast.Empty(tk3)
	ast.Empty(rt3)
}

func TestGeneratePrivateAES(t *testing.T) {
	ast := assert.New(t)
	tk, _, _, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)

	e, err := cls.CreateEncryptKey(tk, "tester1")
	ast.Nil(err)
	ast.NotNil(e)

	e1, err := cls.GetEncryptKey(tk, e.ID)
	ast.Nil(err)

	ast.Equal(e.ID, e1.ID)
	ast.Equal(e.Alg, e1.Alg)
	ast.Equal(e.Key, e1.Key)
	ast.Equal(e.Created, e1.Created)
	ast.Equal(e.Group, e1.Group)
}

func TestGenerateAES(t *testing.T) {
	ast := assert.New(t)
	tk, _, _, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)

	e, err := cls.CreateEncryptKey(tk, "group1")
	ast.Nil(err)
	ast.NotNil(e)

	e1, err := cls.GetEncryptKey(tk, e.ID)
	ast.Nil(err)

	ast.Equal(e.ID, e1.ID)
	ast.Equal(e.Alg, e1.Alg)
	ast.Equal(e.Key, e1.Key)
	ast.Equal(e.Created, e1.Created)
	ast.Equal(e.Group, e1.Group)
}

func TestGenAESWrGroup(t *testing.T) {
	ast := assert.New(t)
	tk, _, _, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)

	e, err := cls.CreateEncryptKey(tk, "group3")
	ast.NotNil(err)
	ast.Nil(e)

	e, err = cls.CreateEncryptKey(tk, "group1")
	ast.Nil(err)
	ast.NotNil(e)

	tk2, _, _, err := cls.Login("345678", "yxcvb")
	ast.Nil(err)

	e1, err := cls.GetEncryptKey(tk2, e.ID)
	ast.NotNil(err)
	ast.Nil(e1)
}

func TestClientCertificate(t *testing.T) {
	ast := assert.New(t)
	tk, _, _, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)

	pub, err := cls.GetCertificate(tk, "tester1")
	ast.Nil(err)
	ast.NotEmpty(pub)

	prv, err := cry.Pem2Pub(pub)
	ast.Nil(err)
	ast.NotNil(prv)
}

func TestSSGroup(t *testing.T) {
	ast := assert.New(t)

	tk1, _, _, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)

	tk2, _, _, err := cls.Login("87654321", "yxcvb")
	ast.Nil(err)

	msg, err := buildGroupMessage("group2")
	ast.Nil(err)

	m, err := cls.CryptSS(tk1, msg)
	ast.Nil(err)

	ast.True(m.Decrypt)
	ast.NotEmpty(m.ID)
	ast.Equal(msg.Recipient, m.Recipient)
	ast.Equal(msg.Type, m.Type)

	m2, err := cls.CryptSS(tk2, *m)
	ast.Nil(err)

	ast.False(m2.Decrypt)
	ast.NotEmpty(m2.ID)
	ast.Equal(m.ID, m2.ID)
	ast.Equal(m.Recipient, m2.Recipient)
	ast.Equal(m.Type, m2.Type)

	ast.Equal(msg.Message, m2.Message)
}

func TestSSGroupWG(t *testing.T) {
	// testing server side crypt with wrong group
	ast := assert.New(t)

	tk1, _, _, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)

	tk2, _, _, err := cls.Login("87654321", "yxcvb")
	ast.Nil(err)

	msg, err := buildGroupMessage("group1")
	ast.Nil(err)

	m, err := cls.CryptSS(tk1, msg)
	ast.Nil(err)

	ast.True(m.Decrypt)
	ast.NotEmpty(m.ID)
	ast.Equal(msg.Recipient, m.Recipient)
	ast.Equal(msg.Type, m.Type)

	m2, err := cls.CryptSS(tk2, *m)
	ast.NotNil(err)
	ast.Nil(m2)
}

func buildGroupMessage(g string) (pmodel.Message, error) {
	adr := struct {
		Lastname  string `json:"lastname"`
		Firstname string `json:"firstname"`
	}{
		Lastname:  "Klaas",
		Firstname: "Wilfried",
	}

	b, err := json.Marshal(adr)
	if err != nil {
		return pmodel.Message{}, err
	}

	msg := pmodel.Message{
		Type:      "group",
		Recipient: g,
		Decrypt:   false,
		Message:   string(b),
	}
	return msg, nil
}

func TestSSClient(t *testing.T) {
	ast := assert.New(t)

	tk1, _, _, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)

	_, _, prvpem, err := cls.Login("87654321", "yxcvb")
	ast.Nil(err)
	ast.NotEmpty(prvpem)

	privateKey, err := cry.Pem2Prv(prvpem)
	ast.Nil(err)
	ast.NotNil(privateKey)

	msg, err := buildClientMessage("tester2")
	ast.Nil(err)

	m, err := cls.CryptSS(tk1, msg)
	ast.Nil(err)

	ast.True(m.Decrypt)
	ast.Empty(m.ID)
	ast.Equal(msg.Recipient, m.Recipient)
	ast.Equal(msg.Type, m.Type)

	ms, err := cry.DecryptKey(*privateKey, m.Message)
	ast.Nil(err)
	ast.Equal(msg.Message, ms)
}

func buildClientMessage(c string) (pmodel.Message, error) {
	adr := struct {
		Lastname  string `json:"lastname"`
		Firstname string `json:"firstname"`
	}{
		Lastname:  "Klaas",
		Firstname: "Wilfried",
	}

	b, err := json.Marshal(adr)
	if err != nil {
		return pmodel.Message{}, err
	}

	msg := pmodel.Message{
		Type:      "private",
		Recipient: c,
		Decrypt:   false,
		Message:   string(b),
	}
	return msg, nil
}

func publicPem(privatekey *rsa.PrivateKey) (string, error) {
	publickey := &privatekey.PublicKey
	pubbuf, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		logging.Logger.Errorf("create public key failed: %v", err)
		return "", err
	}

	pemblock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubbuf,
	}

	b := pem.EncodeToMemory(pemblock)
	return string(b), err
}
func TestMsgStore(t *testing.T) {
	ast := assert.New(t)

	tk1, _, _, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)
	ast.NotEmpty(tk1)

	tk2, _, _, err := cls.Login("87654321", "yxcvb")
	ast.Nil(err)
	ast.NotEmpty(tk2)

	msg := pmodel.Message{
		Type:      "group",
		Origin:    tk1.Name,
		Recipient: "group1",
		Message:   "Dies ist eine Message",
		Decrypt:   false,
	}

	tk1.
}
func TestSSSign(t *testing.T) {
	ast := assert.New(t)

	tk1, _, _, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)
	ast.NotEmpty(tk1)

	tk2, _, _, err := cls.Login("87654321", "yxcvb")
	ast.Nil(err)
	ast.NotEmpty(tk2)

	msg := pmodel.SignMessage{
		Message: "Dies ist eine Message",
		Valid:   false,
	}

	msg2, err := cls.SignSS(tk1, &msg)
	ast.Nil(err)
	ast.NotNil(msg2)

	ast.NotNil(msg2.KeyInfo)
	ast.Equal(msg2.KeyInfo.Alg, "RS256")
	ast.NotEmpty(msg2.KeyInfo.KID)

	msg3, err := cls.CheckSS(tk2, msg2)
	ast.Nil(err)
	ast.NotNil(msg3)
	ast.True(msg3.Valid)
}

func checkToken(tk string, ast *assert.Assertions) {
	jt, err := jwt.Parse([]byte(tk), jwt.WithKey(jwa.RS256, cls.kmn.PrivateKey()))
	ast.Nil(err)
	ast.NotNil(jt)
	auds := jt.Audience()
	ast.True(len(auds) > 0)
	ast.Equal("microvault-client", auds[0])
	n, ok := jt.PrivateClaims()["name"].(string)
	ast.True(ok)
	ast.Equal("tester1", n)
	gs, ok := jt.PrivateClaims()["groups"].([]any)
	ast.True(ok)
	ast.Equal(3, len(gs))
}

func checkRToken(rt string, ast *assert.Assertions) {
	jt, err := jwt.Parse([]byte(rt), jwt.WithKey(jwa.RS256, cls.kmn.PrivateKey()))
	ast.Nil(err)
	ast.NotNil(jt)
	u, ok := jt.PrivateClaims()["usage"].(string)
	ast.True(ok)
	ast.Equal("mv-refresh", u)
	auds := jt.Audience()
	ast.True(len(auds) > 0)
	ast.Equal("microvault-client", auds[0])
	n, ok := jt.PrivateClaims()["name"].(string)
	ast.True(ok)
	ast.Equal("tester1", n)
}
