package keyman

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
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
	cfg    config.Config
	CACert Cert
	caX509 x509.Certificate
}

// DoCAService dependency injection service name
const DoCAService = "cacert"

// NewCAService creating a new CA service
func NewCAService() (*CAService, error) {
	c := CAService{
		cfg: do.MustInvokeNamed[config.Config](nil, config.DoServiceConfig),
	}

	err := c.init()
	if err != nil {
		return nil, err
	}
	do.ProvideNamedValue[CAService](nil, DoCAService, c)
	return &c, nil
}

// X509Cert getting the X509 certificate as pem
func (c *CAService) X509Cert() (string, error) {
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
	cnf := c.cfg.Service.CACert
	if cnf.PrivateKey == "" {
		return errors.New("CA Cert Config should not be nil")
	}
	if !fileExists(cnf.PrivateKey) {
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
	f := c.cfg.Service.CACert.PrivateKey
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

	f = c.cfg.Service.CACert.Certificate
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
	f := c.cfg.Service.CACert.PrivateKey
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

	f = c.cfg.Service.CACert.Certificate
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
	// create the root certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"MCS"},
			Country:       []string{"DE"},
			Province:      []string{""},
			Locality:      []string{"Hattingen"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"45525"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	// create a private key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
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
	return nil
}

func (c *CAService) CreateCertificate() (*Cert, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, &c.caX509, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	return &Cert{caX509: certPEM.Bytes(), caPrivateKey: certPrivKeyPEM.Bytes()}, nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
