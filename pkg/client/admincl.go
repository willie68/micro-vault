package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/willie68/micro-vault/internal/logging"
	"golang.org/x/net/context"
)

// AdminCl this is the admin client
type AdminCl struct {
	url      string
	username string
	password []byte
	token    string
	expired  time.Time
	clt      http.Client
	ctx      context.Context
	insecure bool
}

func (a *AdminCl) init(u string) error {
	timeout := time.Second * 5
	a.insecure = false
	ul, err := url.Parse(u)
	if err != nil {
		return err
	}
	if ul.Hostname() == "127.0.0.1" {
		a.insecure = true
		timeout = time.Second * 360
	}
	a.url = fmt.Sprintf("%s/api/v1", u)
	a.ctx = context.Background()

	tns := &http.Transport{
		// #nosec G402 -- fine for internal traffic
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: a.insecure,
		},
	}

	a.clt = http.Client{
		Timeout:   timeout,
		Transport: tns,
	}
	return nil
}

// Login logging this client in, getting a token for further requests
func (a *AdminCl) Login() error {
	up := struct {
		Username string `json:"user"`
		Password []byte `json:"pwd"`
	}{
		Username: a.username,
		Password: a.password,
	}
	res, err := a.PostJSON("admin/login", up)
	if err != nil {
		logging.Logger.Errorf("login request failed: %v", err)
		return err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("login bad response: %d", res.StatusCode)
		return ReadErr(res)
	}
	ds := struct {
		Token     string `json:"access_token"`
		Type      string `json:"token_type"`
		ExpiresIn int    `json:"expires_in"`
	}{}
	err = ReadJSON(res, &ds)
	if err != nil {
		logging.Logger.Errorf("parsing response failed: %v", err)
		return err
	}
	if ds.Token == "" {
		return errors.New("getting no token")
	}
	a.token = ds.Token
	a.expired = time.Now().Add(time.Second * time.Duration(ds.ExpiresIn))
	return nil
}

// SendPlaybook sending a playbook to the server to initialize the service
func (a *AdminCl) SendPlaybook(pb string) error {
	err := a.checkToken()
	if err != nil {
		return err
	}

	res, err := a.Post("admin/playbook", "application/json", strings.NewReader(pb))
	if err != nil {
		logging.Logger.Errorf("playbook request failed: %v", err)
		return err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("playbook bad response: %d", res.StatusCode)
		return ReadErr(res)
	}
	return nil
}

// PostJSON posting a json string to the endpoint
func (a *AdminCl) PostJSON(endpoint string, body any) (*http.Response, error) {
	byt, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return a.Post(endpoint, "application/json", bytes.NewBuffer(byt))
}

// Post posting something to the endpoint
func (a *AdminCl) Post(endpoint, contentType string, body io.Reader) (*http.Response, error) {
	req, err := a.newRequest(http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return a.do(req)
}

// do a request with logging
func (a *AdminCl) do(req *http.Request) (*http.Response, error) {
	ul := req.URL.RequestURI()
	res, err := a.clt.Do(req)
	if err != nil {
		logging.Logger.Errorf("request %s %s error: %v", req.Method, ul, err)
	} else {
		logging.Logger.Infof("request %s %s returned %s", req.Method, ul, res.Status)
	}
	return res, err
}

func (a *AdminCl) newRequest(method, endpoint string, body io.Reader) (*http.Request, error) {
	ul := fmt.Sprintf("%s/%s", a.url, endpoint)
	logging.Logger.Debugf("creating request %s %s", method, ul)
	req, err := http.NewRequestWithContext(a.ctx, method, ul, body)
	if err != nil {
		logging.Logger.Errorf("cannot create request %s %s", method, ul)
		return nil, err
	}
	if a.token != "" {
		req.Header.Set(tokenHeader, fmt.Sprintf("Bearer %s", a.token))
	}
	logging.Logger.Debugf("request %s %s", method, ul)
	return req, nil
}

func (a *AdminCl) checkToken() error {
	if time.Now().After(a.expired) {
		a.token = ""
		return a.Login()
	}
	return nil
}
