package apiv1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/api"
	"github.com/willie68/micro-vault/internal/auth"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/serror"
	"github.com/willie68/micro-vault/internal/services/admin"
	"github.com/willie68/micro-vault/internal/services/clients"
	"github.com/willie68/micro-vault/internal/utils/httputils"
)

// LoginHandler handler for handling REST calls for admin endpoints
type LoginHandler struct {
	cl  clients.Clients
	adm admin.Admin
	cfg config.Config
}

// NewLoginHandler returning a new REST API Handler for admin endpoints
func NewLoginHandler() api.Handler {
	return &LoginHandler{
		cl:  do.MustInvoke[clients.Clients](nil),
		adm: do.MustInvoke[admin.Admin](nil),
		cfg: do.MustInvoke[config.Config](nil),
	}
}

// Routes getting all routes for the endpoint
func (l *LoginHandler) Routes() (string, *chi.Mux) {
	router := chi.NewRouter()
	router.Post("/", l.PostLogin)
	router.Get("/refresh", l.GetRefresh)
	router.Get("/privatekey", l.GetPrivateKey)
	return BaseURL + loginSubpath, router
}

// PostLogin login a client to the vault service
// @Summary login a client to the vault service
// @Tags configs
// @Accept  json
// @Produce  json
// @Param Accesskey, Secret as strings for login
// @Param payload body string true "Add store"
// @Success 200 {object} token for further processing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/login [post]
func (l *LoginHandler) PostLogin(response http.ResponseWriter, request *http.Request) {
	up := struct {
		Username  string `json:"user"`
		Password  []byte `json:"pwd"`
		AccessKey string `json:"accesskey"`
		Secret    string `json:"secret"`
	}{}
	err := json.NewDecoder(request.Body).Decode(&up)
	if err != nil {
		l.responseOAuthError(response, request, l.wrapOAuthErr(*serror.InternalServerError(err), ErrInvalidRequest))
		return
	}
	isService := up.AccessKey != "" && up.Username == ""
	var t, rt, k string
	if isService {
		t, rt, k, err = l.cl.Login(up.AccessKey, up.Secret)
		if err != nil {
			l.responseOAuthError(response, request, l.wrapOAuthErr(*serror.Wrapc(err, http.StatusBadRequest), ErrInvalidRequest))
			return
		}
	} else {
		t, rt, err = l.adm.LoginUP(up.Username, []byte(up.Password))
		if err != nil {
			l.responseOAuthError(response, request, l.wrapOAuthErr(*serror.Wrapc(err, http.StatusBadRequest), ErrInvalidRequest))
			return
		}
	}
	jt, err := auth.DecodeJWT(t)
	if err != nil {
		l.responseOAuthError(response, request, l.wrapOAuthErr(*serror.Wrapc(err, http.StatusBadRequest), ErrInvalidRequest))
		return
	}
	var name string
	n := jt.Payload["name"]
	if n != nil {
		name = n.(string)
	}
	e := jt.Payload["exp"]
	exp := e.(float64)
	i := jt.Payload["iat"]
	iat := i.(float64)
	tk := struct {
		Name         string `json:"name,omitempty"`
		Token        string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Type         string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Key          string `json:"key,omitempty"`
	}{
		Name:         name,
		Token:        t,
		RefreshToken: rt,
		Type:         "Bearer",
		ExpiresIn:    int(exp - iat),
		Key:          k,
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, tk)
}

// GetRefresh refresh a client to the vault service
// @Summary refresh a client to the vault service
// @Tags configs
// @Accept  json
// @Produce  json
// @Param Accesskey, Secret as strings for login
// @Param payload body string true "Add store"
// @Success 200 {object} token for further processing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/login [post]
func (l *LoginHandler) GetRefresh(response http.ResponseWriter, request *http.Request) {
	rt, err := token(request)
	if err != nil {
		l.responseOAuthError(response, request, l.wrapOAuthErr(*serror.Wrapc(err, http.StatusBadRequest), ErrInvalidRequest))
		return
	}
	jtp, err := jwt.ParseInsecure([]byte(rt))
	if err != nil {
		l.responseOAuthError(response, request, l.wrapOAuthErr(*serror.Wrapc(err, http.StatusBadRequest), ErrInvalidRequest))
		return
	}
	if len(jtp.Audience()) != 1 {
		l.responseOAuthError(response, request, l.wrapOAuthErr(*serror.Wrapc(err, http.StatusBadRequest), ErrInvalidRequest))
		return
	}
	aud := jtp.Audience()[0]
	var t string
	if aud == clients.JKAudience {
		t, rt, err = l.cl.Refresh(rt)
		if err != nil {
			l.responseOAuthError(response, request, l.wrapOAuthErr(*serror.Wrapc(err, http.StatusBadRequest), ErrInvalidRequest))
			return
		}
	}
	if aud == admin.JKAudience {
		t, rt, err = l.adm.Refresh(rt)
		if err != nil {
			l.responseOAuthError(response, request, l.wrapOAuthErr(*serror.Wrapc(err, http.StatusBadRequest), ErrInvalidRequest))
			return
		}
	}
	jt, err := auth.DecodeJWT(t)
	if err != nil {
		l.responseOAuthError(response, request, l.wrapOAuthErr(*serror.Wrapc(err, http.StatusBadRequest), ErrInvalidRequest))
		return
	}
	var name string
	n := jt.Payload["name"]
	if n != nil {
		name = n.(string)
	}
	e := jt.Payload["exp"]
	exp := e.(float64)
	i := jt.Payload["iat"]
	iat := i.(float64)
	tk := struct {
		Name         string `json:"name,omitempty"`
		Token        string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Type         string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}{
		Name:         name,
		Token:        t,
		RefreshToken: rt,
		Type:         "Bearer",
		ExpiresIn:    int(exp - iat),
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, tk)
}

// GetPrivateKey getting the personal private key of a client certificate
// @Summary getting the personal private key of a client certificate
// @Tags configs
// @Accept  pem file
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/certificate/{name} [post]
func (l *LoginHandler) GetPrivateKey(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}

	ct, err := l.cl.GetPrivateKey(tk)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	render.Status(request, http.StatusOK)
	response.Header().Add("Content-Type", "application/x-pem-file")
	_, err = response.Write([]byte(ct))
	if err != nil {
		logger.Errorf("error writing PEM: %v", err)
	}
}

// OAuthErr error description for an OAuth error
type OAuthErr struct {
	serror.Serr
	OError string `json:"error"`
	ODesc  string `json:"error_description"`
	OUri   string `json:"error_uri"`
}

func (o *OAuthErr) Error() string {
	if o.Key == "" {
		o.Key = "unexpected-error"
	}
	byt, err := json.Marshal(o)
	if err != nil {
		return o.str()
	}
	return string(byt)
}

func (o *OAuthErr) str() string {
	s := make([]string, 0)
	if o.Msg != "" {
		s = append(s, o.Msg)
	}
	s = append(s, fmt.Sprintf(", code: %d", o.Code))
	s = append(s, fmt.Sprintf(", key: %s", o.Key))
	if o.Srv != "" {
		s = append(s, fmt.Sprintf(", service: %s", o.Srv))
	}
	if o.Origin != "" {
		s = append(s, fmt.Sprintf(", origin: %s", o.Origin))
	}
	if o.OError != "" {
		s = append(s, fmt.Sprintf(", error: %s", o.OError))
	}
	if o.ODesc != "" {
		s = append(s, fmt.Sprintf(", error_description: %s", o.ODesc))
	}
	if o.OUri != "" {
		s = append(s, fmt.Sprintf(", error_uri: %s", o.OUri))
	}
	return strings.Join(s, "")
}

const (
	// ErrInvalidRequest The request is missing a parameter so the server can’t proceed with the request. This may also be returned if the request includes an unsupported parameter or repeats a parameter.
	ErrInvalidRequest string = "invalid_request"
	// ErrInvalidClient Client authentication failed, such as if the request contains an invalid client ID or secret. Send an HTTP 401 response in this case.
	ErrInvalidClient string = "invalid_client"
	// ErrInvalidGrant The authorization code (or user’s password for the password grant type) is invalid or expired. This is also the error you would return if the redirect URL given in the authorization grant does not match the URL provided in this access token request.
	ErrInvalidGrant string = "invalid_grant"
	// ErrInvalidScope For access token requests that include a scope (password or client_credentials grants), this error indicates an invalid scope value in the request.
	ErrInvalidScope string = "invalid_scope"
	// ErrUnauthorizedClient This client is not authorized to use the requested grant type. For example, if you restrict which applications can use the Implicit grant, you would return this error for the other apps.
	ErrUnauthorizedClient string = "unauthorized_client"
	// ErrUnsupportedGrantType If a grant type is requested that the authorization server doesn’t recognize, use this code. Note that unknown grant types also use this specific error code rather than using the invalid_request above.
	ErrUnsupportedGrantType string = "unsupported_grant_type"
)

func (l *LoginHandler) wrapOAuthErr(serr serror.Serr, oautherr string) *OAuthErr {
	s := serr.Origin
	if s == "" {
		s = serr.Msg
	}
	oer := OAuthErr{
		Serr:   serr,
		OError: oautherr,
		ODesc:  s,
		OUri:   fmt.Sprintf("See the full API docs at %s/docs/authentication", l.cfg.Service.HTTP.ServiceURL),
	}
	return &oer
}

// Err writes an error response
func (l *LoginHandler) responseOAuthError(w http.ResponseWriter, r *http.Request, err *OAuthErr) {
	render.Status(r, err.Code)
	render.JSON(w, r, err)
}
