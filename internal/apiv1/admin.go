package apiv1

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"

	"github.com/cloudflare/cfssl/certinfo"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/api"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/serror"
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
		cl:  do.MustInvoke[clients.Clients](nil),
		adm: do.MustInvoke[admin.Admin](nil),
	}
}

// Routes getting all routes for the endpoint
func (a *AdminHandler) Routes() (string, *chi.Mux) {
	router := chi.NewRouter()
	router.Post("/playbook", a.PostPlaybook)
	rtGroups := "/groups"
	router.Get(rtGroups, a.GetGroups)
	router.Post(rtGroups, a.PostGroups)
	rtGroupName := rtGroups + "/{name}"
	router.Get(rtGroupName, a.GetGroup)
	router.Post(rtGroupName, a.PostGroup)
	router.Delete(rtGroupName, a.DeleteGroup)
	rtClients := "/clients"
	router.Get(rtClients, a.GetClients)
	router.Post(rtClients, a.PostNewClient)
	rtClientName := rtClients + "/{name}"
	router.Delete(rtClientName, a.DeleteClient)
	router.Post(rtClientName, a.PostClient)
	router.Get(rtClientName, a.GetClient)
	router.Get("/groupkeys", a.GetKeys)
	router.Post("/groupkeys", a.PostKey)
	router.Post("/utils/decodecert", a.PostDecodeCertificate)
	router.Get("/info", a.GetInfo)
	return BaseURL + adminSubpath, router
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
	render.NoContent(response, request)
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
	ngs := make([]model.Group, 0)
	for _, g := range gs {
		ng := model.Group{
			Name:     g.Name,
			Label:    g.Label,
			IsClient: g.IsClient,
		}
		ngs = append(ngs, ng)
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, ngs)
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
		Name:     g.Name,
		Label:    g.Label,
		IsClient: g.IsClient,
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, gs)
}

// PostGroup updates a group
// @Summary updates a group
// @Tags configs
// @Accept  name string
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
	n := chi.URLParam(request, "name")
	ok := a.adm.HasGroup(tk, n)
	if !ok {
		httputils.Err(response, request, serror.NotFound("group", n))
		return
	}
	if b, err = io.ReadAll(request.Body); err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	du := pmodel.Group{}
	err = json.Unmarshal(b, &du)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	g := model.Group{
		Name:  du.Name,
		Label: du.Label,
	}
	n, err = a.adm.UpdateGroup(tk, g)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	g, err = a.adm.Group(tk, n)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	gs := pmodel.Group{
		Name:     g.Name,
		Label:    g.Label,
		IsClient: g.IsClient,
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, gs)
}

// PostGroups creating a new group
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
func (a *AdminHandler) PostGroups(response http.ResponseWriter, request *http.Request) {
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
		Name:     pg.Name,
		Label:    pg.Label,
		IsClient: false,
	}
	n, err := a.adm.AddGroup(tk, g)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	g, err = a.adm.Group(tk, n)
	gs := pmodel.Group{
		Name:     g.Name,
		Label:    g.Label,
		IsClient: g.IsClient,
	}
	render.Status(request, http.StatusCreated)
	render.JSON(response, request, gs)
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

	g := request.URL.Query().Get("group")

	var cs []model.Client
	if g != "" {
		cs, err = a.adm.Client4Group(tk, g)
	} else {
		cs, err = a.adm.Clients(tk)
	}
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
			Crt:       c.Crt,
		})
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, cls)
}

// GetClient get a client
// @Summary gets a client
// @Tags configs
// @Accept  name string
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /admin/client/{name} [post]
func (a *AdminHandler) GetClient(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}

	n := chi.URLParam(request, "name")
	ok := a.adm.HasClient(tk, n)
	if !ok {
		httputils.Err(response, request, serror.NotFound("client", n))
		return
	}
	c, err := a.adm.Client(tk, n)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	cs := pmodel.Client{
		Name:      c.Name,
		AccessKey: c.AccessKey,
		Secret:    "",
		Groups:    c.Groups,
		KID:       c.KID,
		Key:       c.Key,
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, cs)
}

// PostNewClient creating a new client
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
func (a *AdminHandler) PostNewClient(response http.ResponseWriter, request *http.Request) {
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
		if errors.Is(err, serror.ErrNotExists) {
			httputils.Err(response, request, serror.NotFound("client", n))
			return
		}
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	render.Status(request, http.StatusOK)
}

// PostClient posting changes to a client
// @Summary posting changes to a client
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
		Name   string         `json:"name"`
		Groups []string       `json:"groups"`
		Crt    map[string]any `json:"crt"`
	}{}

	err = json.Unmarshal(b, &du)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	_, err = a.adm.AddGroups2Client(tk, du.Name, du.Groups)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	cl, err := a.adm.ChangeCertificateTemplateClient(tk, du.Name, du.Crt)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	ccl := pmodel.Client{
		Name:      cl.Name,
		AccessKey: cl.AccessKey,
		Secret:    "*****",
		Groups:    cl.Groups,
		Crt:       cl.Crt,
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, ccl)
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
	var cs []model.EncryptKey
	g := request.URL.Query().Get("group")
	if g != "" {
		cs, err = a.adm.Keys4Group(tk, g, 0, 100)
	} else {
		cs, err = a.adm.Keys(tk, 0, 100)
	}
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

// PostKey creating a new group key
// @Summary creating a new group key
// @Tags configs
// @Accept  string
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /admin/groups [post]
func (a *AdminHandler) PostKey(response http.ResponseWriter, request *http.Request) {
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
	pg := struct {
		Group string `json:"group"`
	}{}

	err = json.Unmarshal(b, &pg)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	c, err := a.adm.CreateGroupKey(tk, pg.Group)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	cl := pmodel.EncryptKeyInfo{
		Alg:     c.Alg,
		ID:      c.ID,
		Group:   c.Group,
		Key:     c.Key,
		Created: c.Created,
	}
	render.Status(request, http.StatusCreated)
	render.JSON(response, request, cl)
}

// PostDecodeCertificate decoding a certificate
// @Summary decoding a certificate
// @Tags configs
// @Accept  string
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /admin/groups [post]
func (a *AdminHandler) PostDecodeCertificate(response http.ResponseWriter, request *http.Request) {
	var b []byte
	var err error
	var p *pem.Block
	var xc *x509.Certificate
	_, err = token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}

	if b, err = io.ReadAll(request.Body); err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	p, _ = pem.Decode(b)
	if p == nil {
		httputils.Err(response, request, serror.BadRequest(errors.New("can't decode body, not a PEM format")))
		return
	}

	if xc, err = x509.ParseCertificate(p.Bytes); err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	certInfo := certinfo.ParseCertificate(xc)
	render.Status(request, http.StatusOK)
	render.JSON(response, request, certInfo)
}

// GetInfo getting service information
// @Summary getting service informations
// @Tags configs
// @Produce  n.n.
// @Param token as authentication header
// @Param payload info file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /admin/groupkeys [post]
func (a *AdminHandler) GetInfo(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	infos, err := a.adm.GetInfo(tk)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusInternalServerError))
		return
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, infos)
}
