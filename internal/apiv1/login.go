package apiv1

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/api"
	"github.com/willie68/micro-vault/internal/auth"
	"github.com/willie68/micro-vault/internal/serror"
	"github.com/willie68/micro-vault/internal/services/admin"
	"github.com/willie68/micro-vault/internal/services/clients"
	"github.com/willie68/micro-vault/internal/utils/httputils"
)

// LoginHandler handler for handling REST calls for admin endpoints
type LoginHandler struct {
	cl  clients.Clients
	adm admin.Admin
}

// NewLoginHandler returning a new REST API Handler for admin endpoints
func NewLoginHandler() api.Handler {
	return &LoginHandler{
		cl:  do.MustInvokeNamed[clients.Clients](nil, clients.DoClients),
		adm: do.MustInvokeNamed[admin.Admin](nil, admin.DoAdmin),
	}
}

// Routes getting all routes for the endpoint
func (l *LoginHandler) Routes() (string, *chi.Mux) {
	router := chi.NewRouter()
	router.Post("/", l.PostLogin)
	router.Get("/refresh", l.GetRefresh)
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
		httputils.Err(response, request, serror.InternalServerError(err))
		return
	}
	isService := up.AccessKey != "" && up.Username == ""
	var t, rt, k string
	if isService {
		t, rt, k, err = l.cl.Login(up.AccessKey, up.Secret)
		if err != nil {
			httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
			return
		}
	} else {
		t, rt, err = l.adm.LoginUP(up.Username, []byte(up.Password))
		if err != nil {
			httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
			return
		}
	}
	jt, err := auth.DecodeJWT(t)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
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
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	jtp, err := jwt.ParseInsecure([]byte(rt))
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	if len(jtp.Audience()) != 1 {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	aud := jtp.Audience()[0]
	var t string
	if aud == clients.JKAudience {
		t, rt, err = l.cl.Refresh(rt)
		if err != nil {
			httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
			return
		}
	}
	if aud == admin.JKAudience {
		t, rt, err = l.adm.Refresh(rt)
		if err != nil {
			httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
			return
		}
	}
	jt, err := auth.DecodeJWT(t)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
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
