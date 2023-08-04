package client

import (
	"time"

	"github.com/willie68/micro-vault/internal/auth"
	"github.com/willie68/micro-vault/internal/logging"
)

// LoginAdminUP login an admin via username password
func LoginAdminUP(u string, p []byte, url string) (*AdminCl, error) {
	logging.Logger.Infof("login as admin with user with password: %s %v", u, len(p) > 0)
	acl := &AdminCl{
		username: u,
		password: p,
	}
	err := acl.init(url)
	if err != nil {
		return nil, err
	}
	err = acl.Login()
	if err != nil {
		return nil, err
	}
	return acl, nil
}

// LoginAdminCli login an admin via token/refreshtoken
func LoginAdminCli(t, rt string, url string, f Refreshcallback) (*AdminCl, error) {
	logging.Logger.Info("login as admin with token")
	exp := expires(t)
	acl := &AdminCl{
		token:           t,
		refreshToken:    rt,
		url:             url,
		expired:         time.Unix(exp, 0),
		refreshcallback: f,
	}
	err := acl.init(url)
	if err != nil {
		return nil, err
	}
	return acl, nil
}

// LoginClientCli login a client via  token/refreshtoken
func LoginClientCli(t, rt string, url string, f Refreshcallback) (*Client, error) {
	logging.Logger.Info("login as a client with token")
	exp := expires(t)
	cl := &Client{
		token:           t,
		refreshToken:    rt,
		url:             url,
		expired:         time.Unix(exp, 0),
		refreshcallback: f,
	}
	err := cl.init(url)
	if err != nil {
		return nil, err
	}
	return cl, nil
}

// LoginClient logging in as a client service
func LoginClient(accesskey, secret, url string) (*Client, error) {
	logging.Logger.Infof("login as service with access key with secret: %s %v", accesskey, len(secret) > 0)

	cl := Client{
		accessKey: accesskey,
		secret:    secret,
	}
	err := cl.init(url)
	if err != nil {
		return nil, err
	}
	err = cl.Login()
	if err != nil {
		return nil, err
	}
	return &cl, nil
}

// ClientBuilder creating a new Client with a fluid builder pattern
type ClientBuilder struct {
	acc  string
	sec  string
	burl string
}

// NewClient fluid starting point creating a new client
func NewClient() *ClientBuilder {
	return &ClientBuilder{}
}

// WithAccessKey adding the access key
func (c *ClientBuilder) WithAccessKey(accessKey string) *ClientBuilder {
	c.acc = accessKey
	return c
}

// WithSecret ading the secret
func (c *ClientBuilder) WithSecret(secret string) *ClientBuilder {
	c.sec = secret
	return c
}

// WithBaseURL adding the base URL to the mv service
func (c *ClientBuilder) WithBaseURL(baseURL string) *ClientBuilder {
	c.burl = baseURL
	return c
}

// Login loggin the client in
func (c *ClientBuilder) Login() (*Client, error) {
	return LoginClient(c.acc, c.sec, c.burl)
}

// AdminBuilder creating a new admin client with a fluid builder pattern
type AdminBuilder struct {
	username string
	password []byte
	burl     string
}

// NewAdmin fluid starting point creating a new admin client
func NewAdmin() *AdminBuilder {
	return &AdminBuilder{}
}

// WithUser login with this user
func (a *AdminBuilder) WithUser(user string) *AdminBuilder {
	a.username = user
	return a
}

// WithPassword login with this user password
func (a *AdminBuilder) WithPassword(pwd []byte) *AdminBuilder {
	a.password = pwd
	return a
}

// WithBaseURL adding the base URL to the mv service
func (a *AdminBuilder) WithBaseURL(baseURL string) *AdminBuilder {
	a.burl = baseURL
	return a
}

// Login loggin the admin client in
func (a *AdminBuilder) Login() (*AdminCl, error) {
	return LoginAdminUP(a.username, a.password, a.burl)
}

func expires(t string) int64 {
	at, err := auth.DecodeJWT(t)
	if err != nil {
		return 0
	}
	expd, ok := at.Payload["exp"]
	if !ok {
		return 0
	}
	expf, ok := expd.(float64)
	if !ok {
		return 0
	}
	return int64(expf)
}
