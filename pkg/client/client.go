package client

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/internal/serror"
	cry "github.com/willie68/micro-vault/pkg/crypt"
	"github.com/willie68/micro-vault/pkg/pmodel"
	"golang.org/x/net/context"
)

const tokenHeader = "Authorization"

// Client the main client for the service calls
type Client struct {
	url        string
	accessKey  string
	secret     string
	name       string
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
		logging.Logger.Errorf("login request failed: %v", err)
		return err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("login bad response: %d", res.StatusCode)
		return ReadErr(res)
	}
	ds := struct {
		Name      string `json:"name"`
		Token     string `json:"access_token"`
		Type      string `json:"token_type"`
		ExpiresIn int    `json:"expires_in"`
		Key       string `json:"key"`
	}{}
	err = ReadJSON(res, &ds)
	if err != nil {
		logging.Logger.Errorf("parsing response failed: %v", err)
		return err
	}
	if ds.Token == "" {
		return errors.New("getting no token")
	}
	c.token = ds.Token
	c.name = ds.Name
	c.expired = time.Now().Add(time.Second * time.Duration(ds.ExpiresIn))
	c.privatekey, err = cry.Pem2Prv(ds.Key)
	if err != nil {
		return err
	}
	return nil
}

// Token returning the token if present
func (c *Client) Token() string {
	return c.token
}

// Name returning the name if present
func (c *Client) Name() string {
	return c.name
}

// Logout logging out this client
func (c *Client) Logout() {
	c.token = ""
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
		logging.Logger.Errorf("key request failed: %v", err)
		return "", "", err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("key bad response: %d", res.StatusCode)
		return "", "", ReadErr(res)
	}
	jr := struct {
		ID  string `json:"id"`
		Alg string `json:"alg"`
		Key string `json:"key"`
	}{}
	err = ReadJSON(res, &jr)
	if err != nil {
		logging.Logger.Errorf("json convert failed: %v", err)
		return "", "", err
	}
	b, err := hex.DecodeString(jr.Key)
	if err != nil {
		logging.Logger.Errorf("hex convert failed: %v", err)
		return "", "", err
	}
	cs, err := cry.Encrypt(b, dt)
	if err != nil {
		logging.Logger.Errorf("reconstruct cipher failed: %v", err)
		return "", "", err
	}
	return cs, jr.ID, err
}

// Decrypt4Group encrypting data string for a group
func (c *Client) Decrypt4Group(id, dt string) (string, error) {
	err := c.checkToken()
	if err != nil {
		return "", err
	}

	res, err := c.Get(fmt.Sprintf("vault/keys/%s", id))
	if err != nil {
		logging.Logger.Errorf("key request failed: %v", err)
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("key bad response: %d", res.StatusCode)
		return "", ReadErr(res)
	}
	jr := struct {
		ID  string `json:"id"`
		Alg string `json:"alg"`
		Key string `json:"key"`
	}{}
	err = ReadJSON(res, &jr)
	b, err := hex.DecodeString(jr.Key)
	if err != nil {
		logging.Logger.Errorf("hex convert failed: %v", err)
		return "", err
	}
	cs, err := cry.Decrypt(b, dt)
	if err != nil {
		logging.Logger.Errorf("reconstruct cipher failed: %v", err)
		return "", err
	}
	return cs, err
}

// Encrypt4Client encrypting data string for a special client
func (c *Client) Encrypt4Client(n, dt string) (string, error) {
	pub, err := c.GetPublicKey(n)
	if err != nil {
		return "", err
	}

	cs, err := cry.EncryptPEM(pub, dt)
	if err != nil {
		logging.Logger.Errorf("encryption failed: %v", err)
		return "", err
	}
	return cs, err
}

// Decrypt4Client encrypting data string for me
func (c *Client) Decrypt4Client(dt string) (string, error) {
	err := c.checkToken()
	if err != nil {
		return "", err
	}

	cs, err := cry.DecryptKey(*c.privatekey, dt)
	if err != nil {
		return "", err
	}
	return cs, err
}

// Sign data with the private key
func (c *Client) Sign(dt string) (*pmodel.SignMessage, error) {
	err := c.checkToken()
	if err != nil {
		return nil, err
	}
	sm := pmodel.SignMessage{
		Message: dt,
	}
	res, err := c.PostJSON("vault/sign", sm)
	if err != nil {
		logging.Logger.Errorf("key request failed: %v", err)
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("key bad response: %d", res.StatusCode)
		return nil, ReadErr(res)
	}
	err = ReadJSON(res, &sm)
	if err != nil {
		logging.Logger.Errorf("read signature failed: %v", err)
		return nil, err
	}
	return &sm, nil
}

// SignCheck data with the public key
func (c *Client) SignCheck(n, sig, dt string) (bool, error) {
	pub, err := c.GetPublicKey(n)
	if err != nil {
		return false, err
	}
	return cry.SignCheckPEM(pub, sig, dt)
}

// SignCheckSS check signature of data on the server side
func (c *Client) SignCheckSS(n string, smsg pmodel.SignMessage) (bool, error) {
	err := c.checkToken()
	if err != nil {
		return false, err
	}
	res, err := c.PostJSON("vault/check", smsg)
	if err != nil {
		logging.Logger.Errorf("key request failed: %v", err)
		return false, err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("key bad response: %d", res.StatusCode)
		return false, ReadErr(res)
	}
	var sm pmodel.SignMessage
	err = ReadJSON(res, &sm)
	if err != nil {
		logging.Logger.Errorf("read signature failed: %v", err)
		return false, err
	}
	return sm.Valid, nil
}

// GetPublicKey getting the public key of another client by name
func (c *Client) GetPublicKey(n string) (string, error) {
	err := c.checkToken()
	if err != nil {
		return "", err
	}

	res, err := c.Get(fmt.Sprintf("vault/certificate/%s", n))
	if err != nil {
		logging.Logger.Errorf("key request failed: %v", err)
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("key bad response: %d", res.StatusCode)
		return "", ReadErr(res)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		logging.Logger.Errorf("hex convert failed: %v", err)
		return "", err
	}
	return string(b), nil
}

// CryptSS doing en/decryption with the message, getting back the en/decryted message
func (c *Client) CryptSS(m pmodel.Message) (*pmodel.Message, error) {
	err := c.checkToken()
	if err != nil {
		return nil, err
	}

	res, err := c.PostJSON("vault/crypt", m)
	if err != nil {
		logging.Logger.Errorf("key request failed: %v", err)
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("key bad response: %d", res.StatusCode)
		return nil, ReadErr(res)
	}
	err = ReadJSON(res, &m)
	if err != nil {
		logging.Logger.Errorf("json convert failed: %v", err)
		return nil, err
	}
	return &m, nil
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
