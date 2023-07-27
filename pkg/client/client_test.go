package client

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"os"
	"testing"

	"log"

	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/pkg/pmodel"
)

func initCl() {
	StartServer()

	if adm == nil {
		ad, err := LoginAdminUP("root", []byte("yxcvb"), "https://127.0.0.1:9543")
		if err != nil {
			panic(err)
		}
		adm = ad
		pb, err := os.ReadFile("./testdata/playbook.json")
		if err != nil {
			panic(err)
		}
		err = adm.SendPlaybook(string(pb))
		if err != nil {
			log.Printf("error in playbook: %v", err)
		}
	}
}

func TestCertificate(t *testing.T) {
	initCl()
	ast := assert.New(t)
	cli, err := LoginClient("12345678", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)

	defer cli.Logout()

	csr, err := createCsrPem()
	ast.Nil(err)
	ast.NotEmpty(csr)

	crt, err := cli.CreateCertificate(*csr)
	ast.Nil(err)
	ast.NotEmpty(crt)

	ast.Equal(1, len(crt.EmailAddresses))
	ast.Equal("info@wk-music.de", crt.EmailAddresses[0])

	ast.Equal(1, len(crt.Subject.Country))
	ast.Equal("AU", crt.Subject.Country[0])

	ast.Equal(1, len(crt.Subject.Organization))
	ast.Equal("Organisation", crt.Subject.Organization[0])
}

func createCsrPem() (*x509.CertificateRequest, error) {
	emailAddress := "info@wk-music.de"
	subj := pkix.Name{
		CommonName:         "MCS",
		Country:            []string{"AU"},
		Province:           []string{"Province"},
		Locality:           []string{"Locality"},
		Organization:       []string{"Organisation"},
		OrganizationalUnit: []string{"OrganisationUnit"},
	}
	rawSubj := subj.ToRDNSequence()

	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		return nil, err
	}
	return &x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, nil
}

func TestRefreshClient(t *testing.T) {
	initCl()
	ast := assert.New(t)
	cli, err := LoginClient("12345678", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)

	defer cli.Logout()

	tk := cli.token
	ex := cli.expired
	rt := cli.refreshToken

	_, err = cli.Sign("willie is signed")
	ast.Nil(err)

	err = cli.Refresh()
	ast.Nil(err)

	ast.NotEqual(tk, cli.token)
	ast.NotEqual(rt, cli.refreshToken)
	ast.NotEqual(ex, cli.expired)

	_, err = cli.Sign("willie is signed")
	ast.Nil(err)
}

func TestEncryptSameUser(t *testing.T) {
	initCl()
	ast := assert.New(t)
	cli, err := LoginClient("12345678", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
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
	initCl()
	ast := assert.New(t)
	cli, err := LoginClient("12345678", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)
	defer cli.Logout()

	cli2, err := LoginClient("87654321", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
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
	initCl()
	ast := assert.New(t)
	cli, err := LoginClient("12345678", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)
	defer cli.Logout()

	cli2, err := LoginClient("87654321", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
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

func TestHMAC(t *testing.T) {
	initCl()
	ast := assert.New(t)
	cli, err := LoginClient("12345678", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)
	defer cli.Logout()

	cli2, err := LoginClient("87654321", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
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

	msg, err := cli.HMAC256("group2", orgtxt)
	ast.Nil(err)
	ast.NotEmpty(msg)
	t.Logf("data: %v", msg)

	ok, err := cli2.HMAC256Verify(*msg)
	ast.Nil(err)
	ast.True(ok)
}

func TestSigning(t *testing.T) {
	initCl()
	ast := assert.New(t)
	cli, err := LoginClient("12345678", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)
	defer cli.Logout()

	cli2, err := LoginClient("87654321", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
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
	ok, err = cli2.SignCheckSS(*sig)
	ast.Nil(err)
	ast.True(ok)

	ok, err = cli2.SignCheck("tester2", sig.Signature, orgtxt)
	ast.NotNil(err)
	ast.False(ok)
}

func TestServerSideCryptGroup(t *testing.T) {
	initCl()
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

	cli, err := LoginClient("12345678", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)
	defer cli.Logout()

	cli2, err := LoginClient("87654321", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
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
	initCl()
	ast := assert.New(t)
	cli, err := LoginClient("12345678", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)
	defer cli.Logout()

	ast.NotEmpty(cli.Token())
	ast.Equal("tester1", cli.Name())
	ast.NotNil(cli.privatekey)
}

func TestSSStore(t *testing.T) {
	initCl()
	ast := assert.New(t)
	cli, err := LoginClient("12345678", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli)
	defer cli.Logout()

	payload := "Dies ist ein Test"

	id, err := cli.StoreDataSS("group2", payload)
	ast.Nil(err)
	ast.NotEmpty(id)

	p, err := cli.GetDataSS(id)
	ast.Nil(err)
	ast.Equal(payload, p)

	cli2, err := LoginClient("87654321", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli2)
	defer cli2.Logout()

	p, err = cli2.GetDataSS(id)
	ast.Nil(err)
	ast.Equal(payload, p)

	cli3, err := LoginClient("345678", "e7d767cd1432145820669be6a60a912e", "https://127.0.0.1:9543")
	ast.Nil(err)
	ast.NotNil(cli3)
	defer cli3.Logout()

	p, err = cli3.GetDataSS(id)
	ast.NotNil(err)
	ast.Empty(p)

	ok, err := cli.DeleteDataSS(id)
	ast.Nil(err)
	ast.True(ok)

	p, err = cli2.GetDataSS(id)
	ast.NotNil(err)
	ast.Empty(p)
}
