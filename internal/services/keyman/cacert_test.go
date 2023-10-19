package keyman

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"testing"
	"time"

	"github.com/samber/do"
	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/config"
)

const (
	keyfile   = "../../../testdata/private3.pem"
	certfile  = "../../../testdata/cert3.pem"
	caKeyfile = "../../../testdata/caprivate.pem"
)

var subjectMap map[string]string

func init() {
	subjectMap = map[string]string{
		"Country":            "de",
		"Organization":       "MCS",
		"OrganizationalUnit": "dev",
		"Locality":           "Hattigen",
		"Province":           "NRW",
		"StreetAddress":      "Welperstraße 65",
		"PostalCode":         "45525",
		"CommonName":         "mcs",
	}
}

func TestNewCaCert(t *testing.T) {
	ast := assert.New(t)

	_ = os.Remove(certfile)

	cfg := config.Config{
		Service: config.Service{
			PrivateKey: keyfile,
			CACert: config.CACert{
				Certificate: certfile,
				Subject:     subjectMap,
			},
		},
	}
	cfg.Provide()

	k, err := NewKeyman()
	ast.Nil(err)
	ast.NotNil(k)

	k1 := do.MustInvoke[Keyman](nil)
	ast.NotNil(k1)

	ca, err := NewCAService()
	ast.Nil(err)
	ast.NotNil(ca)
	ast.True(fileExists(certfile))
	ast.True(fileExists(keyfile))

	ast.NotNil(ca.X509Cert())

	pm, err := ca.X509CertPEM()
	ast.Nil(err)
	p, _ := pem.Decode([]byte(pm))
	ast.NotNil(p)

	ast.Equal("CERTIFICATE", p.Type)

	shutDown(ast)
}

func TestCR(t *testing.T) {
	ast := assert.New(t)

	cfg := config.Config{
		Service: config.Service{
			PrivateKey: keyfile,
			CACert: config.CACert{
				Certificate: certfile,
				Subject:     subjectMap,
			},
		},
	}
	cfg.Provide()

	k, err := NewKeyman()
	ast.Nil(err)
	ast.NotNil(k)

	k1 := do.MustInvoke[Keyman](nil)
	ast.NotNil(k1)

	ca, err := NewCAService()
	ast.Nil(err)
	ast.NotNil(ca)

	cert, err := ca.CreateCertificate()
	ast.Nil(err)
	ast.NotNil(cert)

	p, _ := pem.Decode(cert.caX509)
	ast.Equal("CERTIFICATE", p.Type)

	shutDown(ast)
}

func TestCSR(t *testing.T) {
	ast := assert.New(t)

	cfg := config.Config{
		Service: config.Service{
			PrivateKey: keyfile,
			CACert: config.CACert{
				Certificate: certfile,
				Subject:     subjectMap,
			},
		},
	}
	cfg.Provide()

	k, err := NewKeyman()
	ast.Nil(err)
	ast.NotNil(k)

	k1 := do.MustInvoke[Keyman](nil)
	ast.NotNil(k1)

	ca, err := NewCAService()
	ast.Nil(err)
	ast.NotNil(ca)

	emailAddress := "test@mcs.de"
	subj := pkix.Name{
		CommonName:         "test",
		Country:            []string{"tc"},
		Province:           []string{"tp"},
		Locality:           []string{"tl"},
		Organization:       []string{"to"},
		OrganizationalUnit: []string{"tu"},
		StreetAddress:      []string{"ts"},
		PostalCode:         []string{"tp"},
	}
	rawSubj := subj.ToRDNSequence()

	asn1Subj, err := asn1.Marshal(rawSubj)
	ast.Nil(err)
	template := x509.CertificateRequest{
		RawSubject:     asn1Subj,
		EmailAddresses: []string{emailAddress},
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	ast.Nil(err)

	b, err := ca.CertSignRequest(template, &certPrivKey.PublicKey, time.Hour*24*365)
	ast.Nil(err)
	ast.True(len(b) > 0)

	shutDown(ast)
}

func TestNewPrivateKey(t *testing.T) {
	ast := assert.New(t)

	horg, err := writeCaCert(certfile)
	ast.Nil(err)
	_ = os.Remove(caKeyfile)

	cfg := config.Config{
		Service: config.Service{
			PrivateKey: keyfile,
			CACert: config.CACert{
				PrivateKey:  caKeyfile,
				Certificate: certfile,
				Subject:     subjectMap,
			},
		},
	}
	cfg.Provide()

	k, err := NewKeyman()
	ast.Nil(err)
	ast.NotNil(k)

	k1 := do.MustInvoke[Keyman](nil)
	ast.NotNil(k1)

	ca, err := NewCAService()
	ast.Nil(err)
	ast.NotNil(ca)
	ast.True(fileExists(certfile))
	ast.True(fileExists(keyfile))
	ast.True(fileExists(caKeyfile))
	hnew, err := hash(certfile)
	ast.Nil(err)
	ast.NotEqual(horg, hnew)

	ast.NotNil(ca.X509Cert())

	pm, err := ca.X509CertPEM()
	ast.Nil(err)
	p, _ := pem.Decode([]byte(pm))
	ast.NotNil(p)

	ast.Equal("CERTIFICATE", p.Type)

	shutDown(ast)
}

func writeCaCert(n string) (string, error) {
	err := os.WriteFile(n, []byte(`-----BEGIN CERTIFICATE-----
		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
		VOjVZBQi/hAjg74JDxrLUrxyYgKNXUXflgjX
		-----END CERTIFICATE-----`), os.ModePerm)
	if err != nil {
		return "", err
	}
	return hash(n)
}

func shutDown(ast *assert.Assertions) {
	err := do.Shutdown[config.Config](nil)
	ast.Nil(err)
	err = do.Shutdown[Keyman](nil)
	ast.Nil(err)
	err = do.Shutdown[CAService](nil)
	ast.Nil(err)
}

func hash(n string) (string, error) {
	h := sha256.New()
	f, err := os.Open(n)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
