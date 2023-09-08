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
	cfg       config.CACert
	kmn       Keyman
	caX509    x509.Certificate
	certBytes []byte
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

func (c *CAService) init() error {
	c.kmn = do.MustInvokeNamed[Keyman](nil, DoKeyman)

	if !fileExists(c.cfg.Certificate) {
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

// X509Cert getting the X509 certificate
func (c *CAService) X509Cert() *x509.Certificate {
	return &c.caX509
}

// X509CertPEM getting the X509 certificate as pem
func (c *CAService) X509CertPEM() (string, error) {
	caPEM := new(bytes.Buffer)
	err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.certBytes,
	})
	if err != nil {
		return "", err
	}
	return caPEM.String(), nil
}

func (c *CAService) loadCertificate() error {
	f := c.cfg.Certificate
	b, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return errors.New("no pem block found")
	}
	if p.Type != "CERTIFICATE" {
		return errors.New("wrong pem block found")
	}
	c.certBytes = p.Bytes
	xc, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return err
	}
	c.caX509 = *xc
	return nil
}

func (c *CAService) saveCertificate() error {
	f := c.cfg.Certificate
	p := filepath.Dir(f)
	err := os.MkdirAll(p, os.ModePerm)
	if err != nil {
		return err
	}

	// Encode x509 certificate to pem
	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.certBytes,
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
	caPrivKey := c.kmn.PrivateKey()
	ser, err := randBigint()
	if err != nil {
		return err
	}

	// create the root certificate
	ca := &x509.Certificate{
		SerialNumber: &ser,
		Subject: pkix.Name{
			Organization:       []string{c.cfg.Subject["Organization"]},
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
		SubjectKeyId:          hashKeyID(caPrivKey.N),
		AuthorityKeyId:        hashKeyID(caPrivKey.N),
	}

	// generate the certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	c.certBytes = caBytes
	c.caX509 = *ca
	return nil
}

// CertSignRequest signing the certificate
func (c *CAService) CertSignRequest(template x509.CertificateRequest, pub any, validTo time.Duration) ([]byte, error) {
	ser, err := randBigint()
	if err != nil {
		return []byte{}, err
	}
	// create client certificate template
	clientCRTTemplate := x509.Certificate{
		Signature:          template.Signature,
		SignatureAlgorithm: template.SignatureAlgorithm,

		PublicKeyAlgorithm: template.PublicKeyAlgorithm,
		PublicKey:          template.PublicKey,
		EmailAddresses:     template.EmailAddresses,
		SerialNumber:       &ser,
		Issuer:             c.caX509.Subject,
		DNSNames:           template.DNSNames,
		IPAddresses:        template.IPAddresses,
		URIs:               template.URIs,
		Subject:            template.Subject,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(validTo),
		AuthorityKeyId:     hashKeyID(c.kmn.PrivateKey().N),
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	return x509.CreateCertificate(rand.Reader, &clientCRTTemplate, &c.caX509, pub, c.kmn.PrivateKey())
}

// CreateCertificate create a usual simple certificate
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
		SubjectKeyId:   hashKeyID(certPrivKey.N),
		AuthorityKeyId: hashKeyID(c.kmn.PrivateKey().N),
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, &c.caX509, &certPrivKey.PublicKey, c.kmn.PrivateKey())
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

func hashKeyID(n *big.Int) []byte {
	h := sha1.New()
	_, err := h.Write(n.Bytes())
	if err != nil {
		return []byte{}
	}
	return h.Sum(nil)
}

func randBigint() (big.Int, error) {
	// Max random value, a 130-bits integer, i.e 2^130 - 1
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))

	// Generate cryptographically strong pseudo-random between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return *big.NewInt(0), err
	}
	return *n, nil
}
