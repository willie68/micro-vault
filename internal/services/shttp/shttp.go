package shttp

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/config"
	log "github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/internal/services/keyman"
)

const (
	// DoSHTTP naming constant for dependency injection
	DoSHTTP = "shttp"
)

// SHttp a service encapsulating http and https server
type SHttp struct {
	cfn     config.Config
	useSSL  bool
	sslsrv  *http.Server
	srv     *http.Server
	Started bool
}

// NewSHttp creates a new shttp service
func NewSHttp(cfn config.Config) (*SHttp, error) {
	sh := SHttp{
		cfn:     cfn,
		Started: false,
	}
	sh.init()

	do.ProvideNamedValue[SHttp](nil, DoSHTTP, sh)

	return &sh, nil
}

func (s *SHttp) init() {
	if s.cfn.Sslport > 0 {
		s.useSSL = true
	}
	s.Started = false
}

// StartServers starting all needed http servers
func (s *SHttp) StartServers(router, healthRouter *chi.Mux) {
	if s.useSSL {
		s.startHTTPSServer(router)
		s.startHTTPServer(healthRouter)
	} else {
		s.startHTTPServer(router)
	}
	s.Started = true
}

// ShutdownServers shutting all servers down
func (s *SHttp) ShutdownServers() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	if err := s.srv.Shutdown(ctx); err != nil {
		log.Logger.Errorf("shutdown http server error: %v", err)
	}
	if s.useSSL {
		if err := s.sslsrv.Shutdown(ctx); err != nil {
			log.Logger.Errorf("shutdown https server error: %v", err)
		}
	}
	s.Started = false
}

func (s *SHttp) startHTTPSServer(router *chi.Mux) {
	gc := GenerateCertificate{
		ServiceName:  config.Servicename,
		Organization: "MCS",
		Host:         "127.0.0.1",
		ValidFor:     10 * 365 * 24 * time.Hour,
		IsCA:         false,
		EcdsaCurve:   "P384",
		Ed25519Key:   false,
	}
	tlsConfig, err := gc.GenerateTLSConfig()
	if err != nil {
		log.Logger.Alertf("could not create tls config. %s", err.Error())
	}
	s.sslsrv = &http.Server{
		Addr:         "0.0.0.0:" + strconv.Itoa(s.cfn.Sslport),
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      router,
		TLSConfig:    tlsConfig,
	}
	go func() {
		log.Logger.Infof("starting https server on address: %s", s.sslsrv.Addr)
		if err := s.sslsrv.ListenAndServeTLS("", ""); err != nil {
			log.Logger.Alertf("error starting server: %s", err.Error())
		}
	}()
}

func (s *SHttp) startHTTPServer(router *chi.Mux) {
	// own http server for the healthchecks
	s.srv = &http.Server{
		Addr:         "0.0.0.0:" + strconv.Itoa(s.cfn.Port),
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      router,
	}
	go func() {
		log.Logger.Infof("starting http server on address: %s", s.srv.Addr)
		if err := s.srv.ListenAndServe(); err != nil {
			log.Logger.Alertf("error starting server: %s", err.Error())
		}
	}()
}

// GenerateCertificate model
type GenerateCertificate struct {
	ServiceName  string
	Organization string
	Host         string
	ValidFrom    string
	ValidFor     time.Duration
	IsCA         bool
	RSABits      int
	EcdsaCurve   string
	Ed25519Key   bool
}

func (gc *GenerateCertificate) publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

// GenerateTLSConfig generates the config
func (gc *GenerateCertificate) GenerateTLSConfig() (*tls.Config, error) {
	var priv any
	var err error
	switch gc.EcdsaCurve {
	case "":
		if gc.Ed25519Key {
			_, priv, err = ed25519.GenerateKey(rand.Reader)
		} else {
			priv, err = rsa.GenerateKey(rand.Reader, gc.RSABits)
		}
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		log.Logger.Fatalf("Unrecognized elliptic curve: %q", gc.EcdsaCurve)
		return nil, err
	}
	if err != nil {
		log.Logger.Fatalf("Failed to generate private key: %v", err)
		return nil, err
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{gc.Organization},
			CommonName:   gc.ServiceName,
		},
	}

	hosts := strings.Split(gc.Host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	ca := do.MustInvokeNamed[keyman.CAService](nil, keyman.DoCAService)

	derBytes, err := ca.CertSignRequest(template, gc.publicKey(priv))
	if err != nil {
		log.Logger.Fatalf("Failed to create certificate: %v", err)
		return nil, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Logger.Fatalf("Unable to marshal private key: %v", err)
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)

	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}, nil
}
