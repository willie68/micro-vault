package cmdutils

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/willie68/micro-vault/internal/auth"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/pkg/client"
)

var (
	url       string
	username  string
	password  string
	accesskey string
	secret    string
	token     string
	admin     bool
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

/*func clients() {
	d, ok := readCLConf()
	if !ok {
		d, err := AdminLogin()
		if err != nil {
			panic(err)
		}
	}
	if !d.Admin {
		logging.Logger.Error("you should be logged in as an admin")
		return
	}
	if d.Expired < time.Now().Unix() {
		logging.Logger.Error("token expired. please log in again")
		return
	}
	adm, err := client.LoginAdminToken(d.Token, d.URL)
	if err != nil {
		logging.Logger.Errorf("error getting clients: %v", err)
		return
	}
	cls, err := adm.Clients()
	if err != nil {
		logging.Logger.Errorf("error getting clients: %v", err)
		return
	}
	fmt.Println("Name, AccessKey, Groups")
	for _, cl := range cls {
		fmt.Printf("%s, %s, %v\r\n", cl.Name, cl.AccessKey, cl.Groups)
	}
}

func login() {
	if username != "" {
		AdminLogin()
		return
	}
	_ = clientLogin()
}
*/

// AdminLogin login into the admin account
func AdminLogin(username, password, url string) (*Conf, error) {
	admin = true
	adm, err := client.LoginAdminUP(username, []byte(password), url)
	if err != nil {
		return nil, err
	}
	log.Printf("logged in, token: %s", adm.Token())
	exp := expires(adm.Token())
	log.Printf("expires: %v", time.Unix(exp, 0))
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

// AdminLogout invalidates an admin session
func AdminLogout() error {
	d := Conf{
		Username: "",
		Token:    "",
		Expired:  int64(0),
		Refresh:  "",
		Admin:    false,
		URL:      "",
	}
	return writeCLConf(d)
}

// AdminClient creates a new ad,min client with the specifig stored configuration
func AdminClient(cfg Conf) (*client.AdminCl, error) {
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
		logging.Logger.Info("token refreshed")
		writeCLConf(cf)
	})
	return adm, err
}

func clientLogin() *Conf {
	admin = true
	cl, err := client.LoginService(accesskey, secret, url)
	if err != nil {
		panic(err)
	}
	log.Printf("logged in, token: %s", cl.Token())
	at, err := auth.DecodeJWT(cl.Token())
	if err != nil {
		logging.Logger.Errorf("error decoding token: %v", err)
		return nil
	}
	expd, ok := at.Payload["exp"]
	if !ok {
		logging.Logger.Errorf("can't find expiration date")
		return nil
	}
	expf, ok := expd.(float64)
	if !ok {
		logging.Logger.Errorf("expiration date wrong format")
		return nil
	}
	exp := int64(expf)
	log.Printf("expires: %v", time.Unix(exp, 0))
	d := Conf{
		Username:  cl.Name(),
		AccessKey: accesskey,
		Token:     cl.Token(),
		Expired:   exp,
		Admin:     false,
		URL:       url,
	}
	writeCLConf(d)
	return &d
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
