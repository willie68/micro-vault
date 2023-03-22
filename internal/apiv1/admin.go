package apiv1

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/api"
	"github.com/willie68/micro-vault/internal/auth"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/serror"
	"github.com/willie68/micro-vault/internal/services"
	"github.com/willie68/micro-vault/internal/services/admin"
	"github.com/willie68/micro-vault/internal/services/clients"
	"github.com/willie68/micro-vault/internal/utils/httputils"
	"github.com/willie68/micro-vault/pkg/pmodel"
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
	router.Get("/groups", a.GetGroups)
	router.Post("/groups", a.PostGroup)
	router.Get("/groups/{name}", a.GetGroup)
	router.Delete("/groups/{name}", a.DeleteGroup)
	router.Get("/clients", a.GetClients)
	router.Post("/clients", a.PostClient)
	router.Delete("/clients/{name}", a.DeleteClient)
	router.Get("/groupkeys", a.GetKeys)
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
		Username string `json:"user"`
		Password []byte `json:"pwd"`
	}{}
	err := json.NewDecoder(request.Body).Decode(&up)
	if err != nil {
		httputils.Err(response, request, serror.InternalServerError(err))
		return
	}
	t, err := a.adm.LoginUP(up.Username, []byte(up.Password))
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
	var pm model.Playbook
	err = json.Unmarshal(b, &pm)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	err = a.adm.Playbook(tk, pm)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	render.Status(request, http.StatusOK)
}

// GetGroups getting a list of groups
// @Summary getting a list of groups
// @Tags configs
// @Accept  pem file
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/certificate [post]
func (a *AdminHandler) GetGroups(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}

	gs, err := a.adm.Groups(tk)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, gs)
}

// GetGroup delete a group
// @Summary gets a group
// @Tags configs
// @Accept  name string
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /admin/groups [post]
func (a *AdminHandler) GetGroup(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}

	n := chi.URLParam(request, "name")
	ok := a.adm.HasGroup(tk, n)
	if !ok {
		httputils.Err(response, request, serror.NotFound("group", n))
		return
	}
	g, err := a.adm.Group(tk, n)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	if !ok {
		httputils.Err(response, request, serror.InternalServerError())
		return
	}
	gs := pmodel.Group{
		Name:  g.Name,
		Label: g.Label,
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, gs)
}

// PostGroup creating a new group
// @Summary creating a new group
// @Tags configs
// @Accept  pmodel.Group
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /admin/groups [post]
func (a *AdminHandler) PostGroup(response http.ResponseWriter, request *http.Request) {
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
	var pg pmodel.Group

	err = json.Unmarshal(b, &pg)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	g := model.Group{
		Name:  pg.Name,
		Label: pg.Label,
	}
	_, err = a.adm.AddGroup(tk, g)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	render.Status(request, http.StatusCreated)
}

// DeleteGroup delete a group
// @Summary delete a  group
// @Tags configs
// @Accept  name string
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /admin/groups [post]
func (a *AdminHandler) DeleteGroup(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}

	n := chi.URLParam(request, "name")
	ok := a.adm.HasGroup(tk, n)
	if !ok {
		httputils.Err(response, request, serror.NotFound("group", n))
		return
	}
	_, err = a.adm.DeleteGroup(tk, n)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	if !ok {
		httputils.Err(response, request, serror.InternalServerError())
		return
	}
	render.Status(request, http.StatusOK)
}

// GetClients getting a list of clients
// @Summary getting a list of clients
// @Tags configs
// @Accept  pem file
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /admin/clients [post]
func (a *AdminHandler) GetClients(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}

	cs, err := a.adm.Clients(tk)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	cls := make([]pmodel.Client, 0)
	for _, c := range cs {
		cls = append(cls, pmodel.Client{
			Name:      c.Name,
			AccessKey: c.AccessKey,
			Groups:    c.Groups,
		})
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, cls)
}

// PostClient creating a new client
// @Summary creating a new client
// @Tags configs
// @Accept  pem file
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /admin/clients [post]
func (a *AdminHandler) PostClient(response http.ResponseWriter, request *http.Request) {
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
	du := struct {
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}{}

	err = json.Unmarshal(b, &du)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	cl, err := a.adm.NewClient(tk, du.Name, du.Groups)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	ccl := pmodel.Client{
		Name:      cl.Name,
		AccessKey: cl.AccessKey,
		Secret:    cl.Secret,
		Groups:    cl.Groups,
	}
	render.Status(request, http.StatusCreated)
	render.JSON(response, request, ccl)
}

// DeleteClient delete a client by name
// @Summary delete a client by name
// @Tags configs
// @Accept  name string
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /admin/groups [post]
func (a *AdminHandler) DeleteClient(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	n := chi.URLParam(request, "name")
	_, err = a.adm.DeleteClient(tk, n)
	if err != nil {
		if errors.Is(err, services.ErrNotExists) {
			httputils.Err(response, request, serror.NotFound("client", n))
			return
		}
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	render.Status(request, http.StatusOK)
}

// GetKeys getting a list of groupkeys
// @Summary getting a list of groupkeys
// @Tags configs
// @Accept  pem file
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /admin/groupkeys [post]
func (a *AdminHandler) GetKeys(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}

	cs, err := a.adm.Keys(tk)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	cls := make([]pmodel.EncryptKeyInfo, 0)
	for _, c := range cs {
		cls = append(cls, pmodel.EncryptKeyInfo{
			Alg:     c.Alg,
			ID:      c.ID,
			Group:   c.Group,
			Key:     c.Key,
			Created: c.Created,
		})
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, cls)
}
