package client

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/internal/serror"
	"golang.org/x/net/context"
)

const tokenHeader = "Authorization"

// Client the main client for the service calls
type Client struct {
	url        string
	accessKey  string
	secret     string
	token      string
	expired    time.Time
	clt        http.Client
	ctx        context.Context
	insecure   bool
	privatekey *rsa.PrivateKey
}

func (c *Client) init(u string) error {
	timeout := time.Second * 5
	c.insecure = false
	ul, err := url.Parse(u)
	if err != nil {
		return err
	}
	if ul.Hostname() == "127.0.0.1" {
		c.insecure = true
		timeout = time.Second * 360
	}
	c.url = fmt.Sprintf("%s/api/v1", u)
	c.ctx = context.Background()

	tns := &http.Transport{
		// #nosec G402 -- fine for internal traffic
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: c.insecure,
		},
	}

	c.clt = http.Client{
		Timeout:   timeout,
		Transport: tns,
	}
	if c.privatekey == nil {
		privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		c.privatekey = privatekey
	}
	return nil
}

// Login logging this client in, getting a token for further requests
func (c *Client) Login() error {
	up := struct {
		AccessKey string `json:"accesskey"`
		Secret    string `json:"secret"`
	}{
		AccessKey: c.accessKey,
		Secret:    c.secret,
	}
	res, err := c.PostJSON("vault/login", up)
	if err != nil {
		logging.Logger.Errorf("convert request failed: %v", err)
		return err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("convert bad response: %d", res.StatusCode)
		return ReadErr(res)
	}
	ds := struct {
		Token     string `json:"access_token"`
		Type      string `json:"token_type"`
		ExpiresIn int    `json:"expires_in"`
	}{}
	err = ReadJSON(res, &ds)
	if err != nil {
		logging.Logger.Errorf("convert request failed: %v", err)
		return err
	}
	if ds.Token == "" {
		return errors.New("getting no token")
	}
	c.token = ds.Token
	c.expired = time.Now().Add(time.Second * time.Duration(ds.ExpiresIn))
	return nil
}

// Logout logging out this client
func (c *Client) Logout() {
	c.token = ""
}

// SendCertificate sending the client certificate (public part) for direct communications
func (c *Client) SendCertificate() error {
	err := c.checkToken()
	if err != nil {
		return err
	}
	publickey := &c.privatekey.PublicKey
	pubbuf, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		logging.Logger.Errorf("convert request failed: %v", err)
		return err
	}

	pemblock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubbuf,
	}

	b := pem.EncodeToMemory(pemblock)

	res, err := c.Post("vault/certificate", "application/x-pem-file", strings.NewReader(string(b)))
	if err != nil {
		logging.Logger.Errorf("convert request failed: %v", err)
		return err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("convert bad response: %d", res.StatusCode)
		return ReadErr(res)
	}
	return nil
}

// Encrypt4Group encrypting data string for a group
func (c *Client) Encrypt4Group(g, dt string) (string, string, error) {
	err := c.checkToken()
	if err != nil {
		return "", "", err
	}

	jd := struct {
		Group string `json:"group"`
	}{
		Group: g,
	}
	res, err := c.PostJSON("vault/keys", jd)
	if err != nil {
		logging.Logger.Errorf("convert request failed: %v", err)
		return "", "", err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("convert bad response: %d", res.StatusCode)
		return "", "", ReadErr(res)
	}
	jr := struct {
		ID  string `json:"id"`
		Alg string `json:"alg"`
		Key string `json:"key"`
	}{}
	err = ReadJSON(res, &jr)
	return jr.Key, jr.ID, err
}

// Get getting something from the endpoint
func (c *Client) Get(endpoint string) (*http.Response, error) {
	req, err := c.newRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

// Post posting something to the endpoint
func (c *Client) Post(endpoint, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.newRequest(http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.do(req)
}

// PostJSON posting a json string to the endpoint
func (c *Client) PostJSON(endpoint string, body any) (*http.Response, error) {
	byt, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return c.Post(endpoint, "application/json", bytes.NewBuffer(byt))
}

// Delete sending a delete to an endpoint
func (c *Client) Delete(endpoint string) (*http.Response, error) {
	req, err := c.newRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

// do a request with logging
func (c *Client) do(req *http.Request) (*http.Response, error) {
	ul := req.URL.RequestURI()
	res, err := c.clt.Do(req)
	if err != nil {
		logging.Logger.Errorf("request %s %s error: %v", req.Method, ul, err)
	} else {
		logging.Logger.Infof("request %s %s returned %s", req.Method, ul, res.Status)
	}
	return res, err
}

func (c *Client) newRequest(method, endpoint string, body io.Reader) (*http.Request, error) {
	ul := fmt.Sprintf("%s/%s", c.url, endpoint)
	logging.Logger.Debugf("creating request %s %s", method, ul)
	req, err := http.NewRequestWithContext(c.ctx, method, ul, body)
	if err != nil {
		logging.Logger.Errorf("cannot create request %s %s", method, ul)
		return nil, err
	}
	if c.token != "" {
		req.Header.Set(tokenHeader, fmt.Sprintf("Bearer %s", c.token))
	}
	logging.Logger.Debugf("request %s %s", method, ul)
	return req, nil
}

func (c *Client) checkToken() error {
	if time.Now().After(c.expired) {
		c.token = ""
		return c.Login()
	}
	return nil
}

// ReadJSON read the given response as json
func ReadJSON(res *http.Response, dst any) error {
	return json.NewDecoder(res.Body).Decode(&dst)
}

// ReadErr read the given response as an error
func ReadErr(res *http.Response) error {
	var serr serror.Serr
	err := ReadJSON(res, &serr)
	if err != nil {
		byt, _ := io.ReadAll(res.Body)
		return serror.New(res.StatusCode, "bad-response", string(byt))
	}
	return &serr
}
