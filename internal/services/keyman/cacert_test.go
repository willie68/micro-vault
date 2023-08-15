package keyman

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/samber/do"
	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/config"
)

const (
	keyfile  = "../../../testdata/private3.pem"
	certfile = "../../../testdata/cert3.pem"
)

func TestNewCaCert(t *testing.T) {
	ast := assert.New(t)

	_ = os.Remove(certfile)

	cfg := config.Config{
		Service: config.Service{
			PrivateKey: keyfile,
			CACert: config.CACert{
				Certificate: certfile,
				Subject: map[string]string{
					"Country":            "de",
					"Organization":       "MCS",
					"OrganizationalUnit": "dev",
					"Locality":           "Hattigen",
					"Province":           "NRW",
					"StreetAddress":      "Welperstraße 65",
					"PostalCode":         "45525",
					"CommonName":         "mcs",
				},
			},
		},
	}
	cfg.Provide()

	k, err := NewKeyman()
	ast.Nil(err)
	ast.NotNil(k)

	k1 := do.MustInvokeNamed[Keyman](nil, DoKeyman)
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

	shutDownNamed()
}

func TestCR(t *testing.T) {
	ast := assert.New(t)

	cfg := config.Config{
		Service: config.Service{
			PrivateKey: keyfile,
			CACert: config.CACert{
				Certificate: certfile,
				Subject: map[string]string{
					"Country":            "de",
					"Organization":       "MCS",
					"OrganizationalUnit": "dev",
					"Locality":           "Hattigen",
					"Province":           "NRW",
					"StreetAddress":      "Welperstraße 65",
					"PostalCode":         "45525",
					"CommonName":         "mcs",
				},
			},
		},
	}
	cfg.Provide()

	k, err := NewKeyman()
	ast.Nil(err)
	ast.NotNil(k)

	k1 := do.MustInvokeNamed[Keyman](nil, DoKeyman)
	ast.NotNil(k1)

	ca, err := NewCAService()
	ast.Nil(err)
	ast.NotNil(ca)

	cert, err := ca.CreateCertificate()
	ast.Nil(err)
	ast.NotNil(cert)

	p, _ := pem.Decode(cert.caX509)
	ast.Equal("CERTIFICATE", p.Type)

	shutDownNamed()
}

func TestCSR(t *testing.T) {
	ast := assert.New(t)

	cfg := config.Config{
		Service: config.Service{
			PrivateKey: keyfile,
			CACert: config.CACert{
				Certificate: certfile,
				Subject: map[string]string{
					"Country":            "de",
					"Organization":       "MCS",
					"OrganizationalUnit": "dev",
					"Locality":           "Hattigen",
					"Province":           "NRW",
					"StreetAddress":      "Welperstraße 65",
					"PostalCode":         "45525",
					"CommonName":         "mcs",
				},
			},
		},
	}
	cfg.Provide()

	k, err := NewKeyman()
	ast.Nil(err)
	ast.NotNil(k)

	k1 := do.MustInvokeNamed[Keyman](nil, DoKeyman)
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

	shutDownNamed()
}

func shutDownNamed() {
	do.ShutdownNamed(nil, config.DoServiceConfig)
	do.ShutdownNamed(nil, DoKeyman)
	do.ShutdownNamed(nil, DoCAService)
}
