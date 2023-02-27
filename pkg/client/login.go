package client

import "github.com/willie68/micro-vault/internal/logging"

// LoginAdmin login an admin via username password
func LoginAdmin(u string, p []byte) (*AdminCL, error) {
	logging.Logger.Infof("login as admin with user with password: %s %v", u, len(p) > 0)
	return &AdminCL{}, nil
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
	err = cl.SendCertificate()
	if err != nil {
		return nil, err
	}
	return &cl, nil
}
