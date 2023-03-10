package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	flag "github.com/spf13/pflag"
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

type conf struct {
	Username  string `json:"username"`
	AccessKey string `json:"accesskey"`
	Token     string `json:"token"`
	Expired   int64  `json:"expired"`
	Admin     bool   `json"admin"`
	URL       string `json:"url"`
}

func init() {
	// variables for parameter override
	flag.StringVarP(&url, "url", "e", "", "endpoint url to use")
	flag.StringVarP(&username, "username", "u", "", "user to login")
	flag.StringVarP(&password, "password", "p", "", "password")
	flag.StringVarP(&accesskey, "accesskey", "a", "", "accesskey")
	flag.StringVarP(&secret, "secret", "s", "", "secret")
	flag.StringVarP(&token, "token", "t", "", "token to use")
	admin = false
}

func main() {
	flag.Parse()
	logging.Logger.SetLevel(logging.Error)
	args := flag.Args()
	switch args[0] {
	case "login":
		login()
	case "clients":
		clients()
	}
}

func clients() {
	d, ok := readCLConf()
	if !ok {
		d = adminLogin()
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
		_ = adminLogin()
		return
	}
	_ = clientLogin()
}

func adminLogin() *conf {
	admin = true
	adm, err := client.LoginAdminUP(username, []byte(password), url)
	if err != nil {
		panic(err)
	}
	log.Printf("logged in, token: %s", adm.Token())
	exp := expires(adm.Token())
	log.Printf("expires: %v", time.Unix(exp, 0))
	d := conf{
		Username: username,
		Token:    adm.Token(),
		Expired:  exp,
		Admin:    true,
		URL:      url,
	}
	writeCLConf(d)
	return &d
}

func clientLogin() *conf {
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
	d := conf{
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

func writeCLConf(d conf) {
	js, err := json.Marshal(d)
	if err != nil {
		logging.Logger.Errorf("error serialize token object: %v", err)
		return
	}
	cfg, err := config.GetDefaultConfigFolder()
	if err != nil {
		logging.Logger.Errorf("error getting user config dir: %v", err)
		return
	}
	cfg = filepath.Join(cfg, "mv_client.json")
	err = os.WriteFile(cfg, js, os.ModePerm)
	if err != nil {
		logging.Logger.Errorf("error writing token object: %v", err)
		return
	}
}

func readCLConf() (*conf, bool) {
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
	var d conf
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
