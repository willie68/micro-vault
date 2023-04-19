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

// LoginAdminCli login an admin via username password
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

// LoginService logging in as a client service
func LoginService(accesskey, secret, url string) (*Client, error) {
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
