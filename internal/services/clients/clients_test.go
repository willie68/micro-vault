package clients

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/auth"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/services/playbook"
	"github.com/willie68/micro-vault/internal/services/storage"
)

var (
	ast *assert.Assertions
	stg interfaces.Storage
	cls Clients
)

func inittest(t *testing.T) {
	ast = assert.New(t)
	var err error
	stg, err = storage.NewMemory()
	ast.Nil(err)
	ast.NotNil(stg)
	pb := playbook.NewPlaybook("../../../testdata/playbook.json", stg)
	err = pb.Play()
	ast.Nil(err)

	cls, err = NewClients(stg)
	ast.Nil(err)
}

func TestClientLogin(t *testing.T) {
	inittest(t)

	tk, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)
	t.Logf("kid: %s, token: %s", cls.KID(), tk)
	jwt, err := auth.DecodeJWT(tk)
	ast.Nil(err)
	ast.NotNil(jwt)
	js, err := json.Marshal(jwt)
	ast.Nil(err)
	t.Logf("token decoded: %s", string(js))
}

func TestGenerateAES(t *testing.T) {
	inittest(t)

	tk, err := cls.Login("12345678", "yxcvb")
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
	inittest(t)

	tk, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)

	e, err := cls.CreateEncryptKey(tk, "group3")
	ast.NotNil(err)
	ast.Nil(e)

	e, err = cls.CreateEncryptKey(tk, "group1")
	ast.Nil(err)
	ast.NotNil(e)

	tk2, err := cls.Login("345678", "yxcvb")
	ast.Nil(err)

	e1, err := cls.GetEncryptKey(tk2, e.ID)
	ast.NotNil(err)
	ast.Nil(e1)
}

func TestClientCertificate(t *testing.T) {
	inittest(t)

	tk, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)

	// generate private key
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	ast.Nil(err)

	publickey := &privatekey.PublicKey
	pubbuf, err := x509.MarshalPKIXPublicKey(publickey)
	ast.Nil(err)

	pemblock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubbuf,
	}

	b := pem.EncodeToMemory(pemblock)
	bs := string(b)
	t.Logf("pem: %s", bs)

	err = cls.SetCertificate(tk, bs)
	ast.Nil(err)

	tk2, err := cls.Login("345678", "yxcvb")
	ast.Nil(err)

	pub, err := cls.GetCertificate(tk2, "tester1")
	ast.Nil(err)
	ast.Equal(bs, pub)
}
