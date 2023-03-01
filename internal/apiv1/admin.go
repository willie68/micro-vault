package apiv1

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/api"
	"github.com/willie68/micro-vault/internal/auth"
	"github.com/willie68/micro-vault/internal/serror"
	"github.com/willie68/micro-vault/internal/services/admin"
	"github.com/willie68/micro-vault/internal/services/clients"
	"github.com/willie68/micro-vault/internal/utils/httputils"
)

// AdminHandler handler for handling REST calls for admin endpoints
type AdminHandler struct {
	cl  clients.Clients
	adm admin.Admin
}

// NewAdminHandler returning a new REST API Handler for admin endpoints
func NewAdminHandler() api.Handler {
	return &AdminHandler{
		cl:  do.MustInvokeNamed[clients.Clients](nil, clients.DoClients),
		adm: do.MustInvokeNamed[admin.Admin](nil, admin.DoAdmin),
	}
}

// Routes getting all routes for the endpoint
func (a *AdminHandler) Routes() (string, *chi.Mux) {
	router := chi.NewRouter()
	router.Post("/login", a.PostLogin)
	router.Post("/playbook", a.PostPlaybook)
	return BaseURL + adminSubpath, router
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
func (a *AdminHandler) PostLogin(response http.ResponseWriter, request *http.Request) {
	up := struct {
		AccessKey string `json:"accesskey"`
		Secret    string `json:"secret"`
	}{}
	err := json.NewDecoder(request.Body).Decode(&up)
	if err != nil {
		httputils.Err(response, request, serror.InternalServerError(err))
		return
	}
	t, err := a.cl.Login(up.AccessKey, up.Secret)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	jt, err := auth.DecodeJWT(t)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	e := jt.Payload["exp"]
	exp := e.(float64)
	i := jt.Payload["iat"]
	iat := i.(float64)
	tk := struct {
		Token     string `json:"access_token"`
		Type      string `json:"token_type"`
		ExpiresIn int    `json:"expires_in"`
	}{
		Token:     t,
		Type:      "Bearer",
		ExpiresIn: int(exp - iat),
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, tk)
}

// PostPlaybook posting the public key of a client certificate for the client
// @Summary posting the public key of a client certificate for the client
// @Tags configs
// @Accept  pem file
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/certificate [post]
func (a *AdminHandler) PostPlaybook(response http.ResponseWriter, request *http.Request) {
	var b []byte
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}

	if b, err = io.ReadAll(request.Body); err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	pem := string(b)

	err = a.cl.SetCertificate(tk, pem)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	render.Status(request, http.StatusOK)
}
