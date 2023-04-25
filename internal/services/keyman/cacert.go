package keyman

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/logging"
)

// Cert the certificate
type Cert struct {
	caX509       []byte
	caPrivateKey []byte
}

// CAService the CA cert service
type CAService struct {
	cfg    config.CACert
	CACert Cert
	caX509 x509.Certificate
	caPrv  rsa.PrivateKey
}

// DoCAService dependency injection service name
const DoCAService = "cacert"

// NewCAService creating a new CA service
func NewCAService() (*CAService, error) {
	cfg := do.MustInvokeNamed[config.Config](nil, config.DoServiceConfig)
	cnf := cfg.Service.CACert
	c := CAService{
		cfg: cnf,
	}

	err := c.init()
	if err != nil {
		return nil, err
	}
	do.ProvideNamedValue[CAService](nil, DoCAService, c)
	return &c, nil
}

// X509Cert getting the X509 certificate
func (c *CAService) X509Cert() *x509.Certificate {
	return &c.caX509
}

// X509CertPEM getting the X509 certificate as pem
func (c *CAService) X509CertPEM() (string, error) {
	caPEM := new(bytes.Buffer)
	err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.CACert.caX509,
	})
	if err != nil {
		return "", err
	}
	return string(caPEM.Bytes()), nil
}

func (c *CAService) init() error {
	if c.cfg.PrivateKey == "" {
		return errors.New("CA Cert Config should not be nil")
	}
	if !fileExists(c.cfg.PrivateKey) {
		err := c.createCert()
		if err != nil {
			logging.Logger.Errorf("error creating certificate: %v", err)
			return err
		}
		err = c.saveCertificate()
		if err != nil {
			logging.Logger.Errorf("error saving certificate: %v", err)
			return err
		}
	} else {
		err := c.loadCertificate()
		if err != nil {
			logging.Logger.Errorf("error loading certificate: %v", err)
			return err
		}
	}
	return nil
}

func (c *CAService) loadCertificate() error {
	f := c.cfg.PrivateKey
	b, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return errors.New("no pem block found")
	}
	if p.Type != "RSA PRIVATE KEY" {
		return errors.New("wrong pem block found")
	}
	c.CACert.caPrivateKey = p.Bytes

	pk, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		return err
	}
	c.caPrv = *pk

	f = c.cfg.Certificate
	b, err = os.ReadFile(f)
	if err != nil {
		return err
	}
	p, _ = pem.Decode(b)
	if p == nil {
		return errors.New("no pem block found")
	}
	if p.Type != "CERTIFICATE" {
		return errors.New("wrong pem block found")
	}
	c.CACert.caX509 = p.Bytes
	xc, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return err
	}
	c.caX509 = *xc
	return nil
}

func (c *CAService) saveCertificate() error {
	f := c.cfg.PrivateKey
	p := filepath.Dir(f)
	err := os.MkdirAll(p, os.ModePerm)
	if err != nil {
		return err
	}

	// Encode private key to pem
	caPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: c.CACert.caPrivateKey,
	})
	if err != nil {
		return err
	}

	err = os.WriteFile(f, caPrivKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return err
	}

	// Encode x509 certificate to pem
	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.CACert.caX509,
	})
	if err != nil {
		return err
	}

	f = c.cfg.Certificate
	p = filepath.Dir(f)
	err = os.MkdirAll(p, os.ModePerm)
	if err != nil {
		return err
	}
	err = os.WriteFile(f, caPEM.Bytes(), os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

func (c *CAService) createCert() error {
	// create a private key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// create the root certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:       []string{c.cfg.Subject["Organisation"]},
			Country:            []string{c.cfg.Subject["Country"]},
			Province:           []string{c.cfg.Subject["Province"]},
			Locality:           []string{c.cfg.Subject["Locality"]},
			StreetAddress:      []string{c.cfg.Subject["StreetAddress"]},
			PostalCode:         []string{c.cfg.Subject["PostalCode"]},
			CommonName:         c.cfg.Subject["CommonName"],
			OrganizationalUnit: []string{c.cfg.Subject["OrganizationalUnit"]},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          hashKeyId(caPrivKey.N),
		AuthorityKeyId:        hashKeyId(caPrivKey.N),
	}

	// generate the certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	xc := x509.MarshalPKCS1PrivateKey(caPrivKey)
	caCert := Cert{
		caX509:       caBytes,
		caPrivateKey: xc,
	}
	c.CACert = caCert
	c.caX509 = *ca
	c.caPrv = *caPrivKey
	return nil
}

func (c *CAService) CertRequest(template x509.Certificate, pub any) ([]byte, error) {
	template.AuthorityKeyId = hashKeyId(c.caPrv.N)
	return x509.CreateCertificate(rand.Reader, &template, &c.caX509, pub, &c.caPrv)
}

func (c *CAService) CreateCertificate() (*Cert, error) {
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:       []string{c.cfg.Subject["Organisation"]},
			Country:            []string{c.cfg.Subject["Country"]},
			Province:           []string{c.cfg.Subject["Province"]},
			Locality:           []string{c.cfg.Subject["Locality"]},
			StreetAddress:      []string{c.cfg.Subject["StreetAddress"]},
			PostalCode:         []string{c.cfg.Subject["PostalCode"]},
			CommonName:         c.cfg.Subject["CommonName"],
			OrganizationalUnit: []string{c.cfg.Subject["OrganizationalUnit"]},
		},
		SubjectKeyId:   hashKeyId(certPrivKey.N),
		AuthorityKeyId: hashKeyId(c.caPrv.N),
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, &c.caX509, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}

	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return nil, err
	}

	return &Cert{caX509: certPEM.Bytes(), caPrivateKey: certPrivKeyPEM.Bytes()}, nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func hashKeyId(n *big.Int) []byte {
	h := sha1.New()
	h.Write(n.Bytes())
	return h.Sum(nil)
}
