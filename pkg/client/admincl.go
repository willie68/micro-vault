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
	"github.com/willie68/micro-vault/pkg/pmodel"
	"golang.org/x/net/context"
)

const (
	errParsingResponse = "parsing response failed: %v"
)

// Refreshcallback this callback is used on a automated refresh to give the library user the actual token and refresh token.
type Refreshcallback func(tk, rt string)

// AdminCl this is the admin client
type AdminCl struct {
	base            string
	url             string
	username        string
	password        []byte
	token           string
	refreshToken    string
	expired         time.Time
	clt             http.Client
	ctx             context.Context
	insecure        bool
	refreshcallback Refreshcallback
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
	a.base = u
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

// GetCACert getting the root certificate of the CA
func (a *AdminCl) GetCACert() (string, error) {
	res, err := a.clt.Get(fmt.Sprintf("%s/%s", a.base, "ca/cacert"))
	if err != nil {
		logging.Logger.Errorf("get cacert request failed: %v", err)
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("get cacert bad response: %d", res.StatusCode)
		return "", ReadErr(res)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		logging.Logger.Errorf("get cacert request body: %v", err)
		return "", err
	}
	return string(b), nil
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
	res, err := a.PostJSON("login", up)
	if err != nil {
		logging.Logger.Errorf("login request failed: %v", err)
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("login bad response: %d", res.StatusCode)
		return ReadErr(res)
	}
	ds := struct {
		Token        string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Type         string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}{}
	err = ReadJSON(res, &ds)
	if err != nil {
		logging.Logger.Errorf(errParsingResponse, err)
		return err
	}
	if ds.Token == "" {
		return errors.New("getting no token")
	}
	a.token = ds.Token
	a.refreshToken = ds.RefreshToken
	a.expired = time.Now().Add(time.Second * time.Duration(ds.ExpiresIn))
	return nil
}

// Logout logging out this client
func (a *AdminCl) Logout() {
	a.token = ""
	a.refreshToken = ""
}

// Refresh refresh the tokens
func (a *AdminCl) Refresh() error {
	a.token = a.refreshToken
	res, err := a.Get("login/refresh")
	if err != nil {
		logging.Logger.Errorf("refresh request failed: %v", err)
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("login bad response: %d", res.StatusCode)
		return ReadErr(res)
	}
	ds := struct {
		Token        string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Type         string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}{}
	err = ReadJSON(res, &ds)
	if err != nil {
		logging.Logger.Errorf(errParsingResponse, err)
		return err
	}
	if ds.Token == "" {
		return errors.New("getting no token")
	}
	a.token = ds.Token
	a.refreshToken = ds.RefreshToken
	a.expired = time.Now().Add(time.Second * time.Duration(ds.ExpiresIn))
	if a.refreshcallback != nil {
		a.refreshcallback(a.token, a.refreshToken)
	}
	return nil
}

// Token returning the token if present
func (a *AdminCl) Token() string {
	return a.token
}

// RefreshToken returning the token if present
func (a *AdminCl) RefreshToken() string {
	return a.refreshToken
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
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		logging.Logger.Errorf("playbook bad response: %d", res.StatusCode)
		return ReadErr(res)
	}
	return nil
}

// Groups getting a list of groups
func (a *AdminCl) Groups() ([]pmodel.Group, error) {
	err := a.checkToken()
	if err != nil {
		return []pmodel.Group{}, err
	}

	res, err := a.Get("admin/groups")
	if err != nil {
		logging.Logger.Errorf("groups request failed: %v", err)
		return []pmodel.Group{}, err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("groups bad response: %d", res.StatusCode)
		return []pmodel.Group{}, ReadErr(res)
	}
	defer res.Body.Close()
	gs := make([]pmodel.Group, 0)
	err = ReadJSON(res, &gs)
	if err != nil {
		logging.Logger.Errorf(errParsingResponse, err)
		return []pmodel.Group{}, err
	}

	return gs, nil
}

// Group getting a group
func (a *AdminCl) Group(n string) (*pmodel.Group, error) {
	err := a.checkToken()
	if err != nil {
		return nil, err
	}

	res, err := a.Get(fmt.Sprintf("admin/groups/%s", n))
	if err != nil {
		logging.Logger.Errorf("group request failed: %v", err)
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("group bad response: %d", res.StatusCode)
		return nil, ReadErr(res)
	}
	defer res.Body.Close()
	var gs pmodel.Group
	err = ReadJSON(res, &gs)
	if err != nil {
		logging.Logger.Errorf(errParsingResponse, err)
		return nil, err
	}

	return &gs, nil
}

// AddGroup adding a new group
func (a *AdminCl) AddGroup(g pmodel.Group) error {
	err := a.checkToken()
	if err != nil {
		return err
	}

	res, err := a.PostJSON("admin/groups", g)
	if err != nil {
		logging.Logger.Errorf("add group request failed: %v", err)
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		logging.Logger.Errorf("add group bad response: %d", res.StatusCode)
		return ReadErr(res)
	}
	return nil
}

// UpdateGroup adding a new group
func (a *AdminCl) UpdateGroup(g pmodel.Group) error {
	err := a.checkToken()
	if err != nil {
		return err
	}

	res, err := a.PostJSON("admin/groups/"+g.Name, g)
	if err != nil {
		logging.Logger.Errorf("update group request failed: %v", err)
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("update group bad response: %d", res.StatusCode)
		return ReadErr(res)
	}
	return nil
}

// DeleteGroup deleting a group
func (a *AdminCl) DeleteGroup(n string) error {
	err := a.checkToken()
	if err != nil {
		return err
	}

	res, err := a.Delete(fmt.Sprintf("admin/groups/%s", n))
	if err != nil {
		logging.Logger.Errorf("delete group request failed: %v", err)
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("delete group bad response: %d", res.StatusCode)
		return ReadErr(res)
	}
	return nil
}

// ClientsOption options for the clients methode
type ClientsOption func(c *ClientsOptionContext)

// WithGroupFilter filter the clients with a group
func WithGroupFilter(g string) ClientsOption {
	// this is the ClientOption function type
	return func(c *ClientsOptionContext) {
		c.groupFilter = g
	}
}

// ClientsOptionContext holding the options for the clients methode
type ClientsOptionContext struct {
	groupFilter string
}

// Clients getting a list of groups
func (a *AdminCl) Clients(opts ...ClientsOption) ([]pmodel.Client, error) {
	err := a.checkToken()
	if err != nil {
		return []pmodel.Client{}, err
	}
	cOpt := &ClientsOptionContext{}
	for _, opt := range opts {
		opt(cOpt)
	}
	q := url.Values{}
	if cOpt.groupFilter != "" {
		q.Add("group", cOpt.groupFilter)
	}
	qs := q.Encode()
	page := "admin/clients"
	if qs != "" {
		page = page + "?" + qs
	}
	res, err := a.Get(page)
	if err != nil {
		logging.Logger.Errorf("clients request failed: %v", err)
		return []pmodel.Client{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("clients bad response: %d", res.StatusCode)
		return []pmodel.Client{}, ReadErr(res)
	}
	cs := make([]pmodel.Client, 0)
	err = ReadJSON(res, &cs)
	if err != nil {
		logging.Logger.Errorf(errParsingResponse, err)
		return []pmodel.Client{}, err
	}

	return cs, nil
}

// Client getting a single client
func (a *AdminCl) Client(n string) (*pmodel.Client, error) {
	err := a.checkToken()
	if err != nil {
		return nil, err
	}
	page := "admin/clients/" + n
	res, err := a.Get(page)
	if err != nil {
		logging.Logger.Errorf("client request failed: %v", err)
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("client bad response: %d", res.StatusCode)
		return nil, ReadErr(res)
	}
	var cs pmodel.Client
	err = ReadJSON(res, &cs)
	if err != nil {
		logging.Logger.Errorf(errParsingResponse, err)
		return nil, err
	}

	return &cs, nil
}

// NewClient getting a list of groups
func (a *AdminCl) NewClient(n string, g []string) (*pmodel.Client, error) {
	err := a.checkToken()
	if err != nil {
		return nil, err
	}
	du := struct {
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}{
		Name:   n,
		Groups: g,
	}
	res, err := a.PostJSON("admin/clients", du)
	if err != nil {
		logging.Logger.Errorf("add client request failed: %v", err)
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		logging.Logger.Errorf("add client bad response: %d", res.StatusCode)
		return nil, ReadErr(res)
	}
	var cs pmodel.Client
	err = ReadJSON(res, &cs)
	if err != nil {
		logging.Logger.Errorf(errParsingResponse, err)
		return nil, err
	}

	return &cs, nil
}

// UpdateClient updating the hroups a client belongs to.
func (a *AdminCl) UpdateClient(n string, g []string) (*pmodel.Client, error) {
	err := a.checkToken()
	if err != nil {
		return nil, err
	}
	du := struct {
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}{
		Name:   n,
		Groups: g,
	}
	res, err := a.PostJSON("admin/clients/"+du.Name, du)
	if err != nil {
		logging.Logger.Errorf("update client request failed: %v", err)
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("update client bad response: %d", res.StatusCode)
		return nil, ReadErr(res)
	}
	var cs pmodel.Client
	err = ReadJSON(res, &cs)
	if err != nil {
		logging.Logger.Errorf(errParsingResponse, err)
		return nil, err
	}

	return &cs, nil
}

// DeleteClient getting a list of groups
func (a *AdminCl) DeleteClient(n string) error {
	err := a.checkToken()
	if err != nil {
		return err
	}

	res, err := a.Delete(fmt.Sprintf("admin/clients/%s", n))
	if err != nil {
		logging.Logger.Errorf("delete client request failed: %v", err)
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("delete client bad response: %d", res.StatusCode)
		return ReadErr(res)
	}
	return nil
}

// DecodeCertificate decoding the certificate into a map
func (a *AdminCl) DecodeCertificate(pem string) (map[string]any, error) {
	err := a.checkToken()
	if err != nil {
		return nil, err
	}
	res, err := a.Post("admin/utils/decodecert", "text/plain", strings.NewReader(pem))
	if err != nil {
		logging.Logger.Errorf("update client request failed: %v", err)
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		logging.Logger.Errorf("update client bad response: %d", res.StatusCode)
		return nil, ReadErr(res)
	}
	cj := make(map[string]any)
	err = ReadJSON(res, &cj)
	if err != nil {
		logging.Logger.Errorf(errParsingResponse, err)
		return nil, err
	}
	return cj, nil
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

// Get getting something from the endpoint
func (a *AdminCl) Get(endpoint string) (*http.Response, error) {
	req, err := a.newRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return a.do(req)
}

// Delete delete a resource
func (a *AdminCl) Delete(endpoint string) (*http.Response, error) {
	req, err := a.newRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return nil, err
	}
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
		err := a.Refresh()
		if err != nil {
			a.token = ""
			a.refreshToken = ""
			return a.Login()
		}
		return nil
	}
	return nil
}
