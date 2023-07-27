package cmdutils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/willie68/micro-vault/internal/auth"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/pkg/client"
)

// Conf the login conf
type Conf struct {
	Username  string `json:"username"`
	AccessKey string `json:"accesskey"`
	Token     string `json:"token"`
	Refresh   string `json:"refresh"`
	Expired   int64  `json:"expired"`
	Admin     bool   `json:"admin"`
	URL       string `json:"url"`
}

// AdminLogin login into the admin account
func AdminLogin(username, password, url string) (*Conf, error) {
	adm, err := client.LoginAdminUP(username, []byte(password), url)
	if err != nil {
		return nil, err
	}
	exp := expires(adm.Token())
	fmt.Printf("login successful, expires: %v\r\n", time.Unix(exp, 0))
	d := Conf{
		Username: username,
		Token:    adm.Token(),
		Expired:  exp,
		Refresh:  adm.RefreshToken(),
		Admin:    true,
		URL:      url,
	}
	err = writeCLConf(d)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// ClientLogin login into the admin account
func ClientLogin(accesskey, secret, url string) (*Conf, error) {
	cli, err := client.LoginClient(accesskey, secret, url)
	if err != nil {
		return nil, err
	}
	exp := expires(cli.Token())
	fmt.Printf("login successful, expires: %v\r\n", time.Unix(exp, 0))
	d := Conf{
		Username:  cli.Name(),
		AccessKey: accesskey,
		Token:     cli.Token(),
		Expired:   exp,
		Refresh:   cli.RefreshToken(),
		Admin:     false,
		URL:       url,
	}
	err = writeCLConf(d)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// ClientLogout invalidates an admin session
func ClientLogout() error {
	cl, ok := ReadCLConf()
	if !ok {
		cl = &Conf{
			Username: "",
			Token:    "",
			Expired:  int64(0),
			Refresh:  "",
			Admin:    false,
			URL:      "https://localhost:8443",
		}
	}
	cl.Token = ""
	cl.Refresh = ""
	return writeCLConf(*cl)
}

// Client creates a new client with the specifig stored configuration
func Client() (*client.Client, error) {
	cfg, ok := ReadCLConf()
	if !ok {
		return nil, errors.New("you're not logged in, please use login command")
	}
	cli, err := client.LoginClientCli(cfg.Token, cfg.Refresh, cfg.URL, func(tk, rt string) {
		cf := Conf{
			Username:  cfg.Username,
			AccessKey: cfg.AccessKey,
			Token:     tk,
			Refresh:   rt,
			Expired:   expires(tk),
			Admin:     cfg.Admin,
			URL:       cfg.URL,
		}
		fmt.Println("token refreshed")
		err := writeCLConf(cf)
		if err != nil {
			fmt.Printf("error writing config: %v\r\n", err)
		}
	})
	return cli, err
}

// AdminLogout invalidates an admin session
func AdminLogout() error {
	cl, ok := ReadCLConf()
	if !ok {
		cl = &Conf{
			Username: "",
			Token:    "",
			Expired:  int64(0),
			Refresh:  "",
			Admin:    true,
			URL:      "https://localhost:8443",
		}
	}
	cl.Token = ""
	cl.Refresh = ""
	return writeCLConf(*cl)
}

// AdminClient creates a new admin client with the specifig stored configuration
func AdminClient() (*client.AdminCl, error) {
	cfg, ok := ReadCLConf()
	if !ok {
		return nil, errors.New("you're not logged in, please use login command")
	}
	adm, err := client.LoginAdminCli(cfg.Token, cfg.Refresh, cfg.URL, func(tk, rt string) {
		cf := Conf{
			Username:  cfg.Username,
			AccessKey: cfg.AccessKey,
			Token:     tk,
			Refresh:   rt,
			Expired:   expires(tk),
			Admin:     cfg.Admin,
			URL:       cfg.URL,
		}
		fmt.Println("token refreshed")
		err := writeCLConf(cf)
		if err != nil {
			fmt.Printf("error writing config: %v\r\n", err)
		}
	})
	return adm, err
}

func writeCLConf(d Conf) error {
	js, err := json.Marshal(d)
	if err != nil {
		logging.Logger.Errorf("error serialize token object: %v", err)
		return err
	}
	cfg, err := config.GetDefaultConfigFolder()
	if err != nil {
		logging.Logger.Errorf("error getting user config dir: %v", err)
		return err
	}
	cfg = filepath.Join(cfg, "mv_client.json")
	err = os.WriteFile(cfg, js, os.ModePerm)
	if err != nil {
		logging.Logger.Errorf("error writing token object: %v", err)
		return err
	}
	return nil
}

// ReadCLConf reading the cl config file, if present
func ReadCLConf() (*Conf, bool) {
	cfg, err := config.GetDefaultConfigFolder()
	if err != nil {
		logging.Logger.Errorf("error getting user config dir: %v", err)
		return nil, false
	}
	cfg = filepath.Join(cfg, "mv_client.json")
	b, err := os.ReadFile(cfg)
	if err != nil {
		logging.Logger.Errorf("error reading config: %v", err)
		return nil, false
	}
	var d Conf
	err = json.Unmarshal(b, &d)
	if err != nil {
		logging.Logger.Errorf("error deserialize json: %v", err)
		return nil, false
	}
	return &d, true
}

func expires(t string) int64 {
	at, err := auth.DecodeJWT(t)
	if err != nil {
		logging.Logger.Errorf("error decoding token: %v", err)
		return 0
	}
	expd, ok := at.Payload["exp"]
	if !ok {
		logging.Logger.Errorf("can't find expiration date")
		return 0
	}
	expf, ok := expd.(float64)
	if !ok {
		logging.Logger.Errorf("expiration date wrong format")
		return 0
	}
	return int64(expf)
}

// OutputCertificate writes the given certificate and private key to the desired files
func OutputCertificate(c x509.Certificate, p rsa.PrivateKey, certFile, privFile string) error {
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
		return err
	}
	if err := certOut.Close(); err != nil {
		return err
	}
	log.Print("wrote cert.pem\n")

	keyOut, err := os.OpenFile(privFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(&p)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}
	if err := keyOut.Close(); err != nil {
		return err
	}
	log.Print("wrote key.pem\n")
	return nil
}
