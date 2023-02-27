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
	"time"

	"github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/internal/serror"
	"golang.org/x/net/context"
)

const tokenHeader = "authentication"

// Client the main client for the service calls
type Client struct {
	url       string
	accessKey string
	secret    string
	token     string
	clt       http.Client
	ctx       context.Context
	insecure  bool
}

func (c *Client) init(u string) error {
	c.insecure = false
	ul, err := url.Parse(u)
	if err != nil {
		return err
	}
	if ul.Hostname() == "127.0.0.1" {
		c.insecure = true
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
		Timeout:   time.Second * 5,
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
		logging.Logger.Errorf("convert request failed: %v", err)
		return err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("convert bad response: %d", res.StatusCode)
		return ReadErr(res)
	}
	ds := struct {
		Token string `json:"token"`
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
	return nil
}

func (c *Client) Get(endpoint string) (*http.Response, error) {
	req, err := c.newRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *Client) Post(endpoint, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.newRequest(http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.do(req)
}

func (c *Client) PostJSON(endpoint string, body any) (*http.Response, error) {
	byt, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return c.Post(endpoint, "application/json", bytes.NewBuffer(byt))
}

func (c *Client) Delete(endpoint string) (*http.Response, error) {
	req, err := c.newRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

// do a request with logging
func (c *Client) do(req *http.Request) (*http.Response, error) {
	url := req.URL.RequestURI()
	res, err := c.clt.Do(req)
	if err != nil {
		logging.Logger.Errorf("request %s %s error: %v", req.Method, url, err)
	} else {
		logging.Logger.Infof("request %s %s returned %s", req.Method, url, res.Status)
	}
	return res, err
}

func (c *Client) newRequest(method, endpoint string, body io.Reader) (*http.Request, error) {
	url := fmt.Sprintf("%s/%s", c.url, endpoint)
	logging.Logger.Debugf("creating request %s %s", method, url)
	req, err := http.NewRequestWithContext(c.ctx, method, url, body)
	if err != nil {
		logging.Logger.Errorf("cannot create request %s %s", method, url)
		return nil, err
	}
	if c.token != "" {
		req.Header.Set(tokenHeader, fmt.Sprintf("Bearer &´%s", c.token))
	}
	logging.Logger.Debugf("request %s %s", method, url)
	return req, nil
}

// ReadJSON read the given response as json
func ReadJSON(res *http.Response, dst any) error {
	if err := json.NewDecoder(res.Body).Decode(&dst); err != nil {
		return err
	}
	return nil
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
