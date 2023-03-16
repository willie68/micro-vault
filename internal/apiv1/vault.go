package apiv1

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/api"
	"github.com/willie68/micro-vault/internal/auth"
	"github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/internal/serror"
	"github.com/willie68/micro-vault/internal/services/clients"
	"github.com/willie68/micro-vault/internal/utils/httputils"
	"github.com/willie68/micro-vault/pkg/pmodel"
)

// VaultHandler handler for handling REST calls for vaults endpoints
type VaultHandler struct {
	cl clients.Clients
}

// NewVaultHandler returning a new REST API Handler for vault endpoints
func NewVaultHandler() api.Handler {
	return &VaultHandler{
		cl: do.MustInvokeNamed[clients.Clients](nil, clients.DoClients),
	}
}

// Routes getting all routes for the config endpoint
func (v *VaultHandler) Routes() (string, *chi.Mux) {
	router := chi.NewRouter()
	router.Post("/clients/login", v.PostLogin)
	router.Get("/clients/certificate/{name}", v.GetCert)
	router.Post("/groups/keys", v.PostKeys)
	router.Get("/groups/keys/{id}", v.GetKey)
	router.Post("/groups/crypt", v.PostCrypt)
	router.Post("/signature/sign", v.PostSign)
	router.Post("/signature/check", v.PostCheck)
	return BaseURL + vaultSubpath, router
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
func (v *VaultHandler) PostLogin(response http.ResponseWriter, request *http.Request) {
	up := struct {
		AccessKey string `json:"accesskey"`
		Secret    string `json:"secret"`
	}{}
	err := json.NewDecoder(request.Body).Decode(&up)
	if err != nil {
		httputils.Err(response, request, serror.InternalServerError(err))
		return
	}
	t, k, err := v.cl.Login(up.AccessKey, up.Secret)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	jt, err := auth.DecodeJWT(t)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	n := jt.Payload["name"]
	name := n.(string)
	e := jt.Payload["exp"]
	exp := e.(float64)
	i := jt.Payload["iat"]
	iat := i.(float64)
	tk := struct {
		Name      string `json:"name"`
		Token     string `json:"access_token"`
		Type      string `json:"token_type"`
		ExpiresIn int    `json:"expires_in"`
		Key       string `json:"key"`
	}{
		Name:      name,
		Token:     t,
		Type:      "Bearer",
		ExpiresIn: int(exp - iat),
		Key:       k,
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, tk)
}

// GetCert getting the public key of a client certificate for the named client
// @Summary getting the public key of a client certificate for the named client
// @Tags configs
// @Accept  pem file
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/certificate/{name} [post]
func (v *VaultHandler) GetCert(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}

	name := chi.URLParam(request, "name")
	if name == "" {
		httputils.Err(response, request, serror.Wrapc(errors.New("name should not be empty"), http.StatusBadRequest))
		return
	}
	ct, err := v.cl.GetCertificate(tk, name)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	render.Status(request, http.StatusOK)
	response.Header().Add("Content-Type", "application/x-pem-file")
	_, err = response.Write([]byte(ct))
	if err != nil {
		logging.Logger.Errorf("error writing PEM: %v", err)
	}
}

// PostKeys posting data to generate a new key for group
// @Summary posting data to generate a new key for group
// @Tags configs
// @Accept  pem file
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/keys [post]
func (v *VaultHandler) PostKeys(response http.ResponseWriter, request *http.Request) {
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	jd := struct {
		Group string `json:"group"`
	}{}
	err = json.NewDecoder(request.Body).Decode(&jd)
	if err != nil {
		httputils.Err(response, request, serror.InternalServerError(err))
		return
	}

	ek, err := v.cl.CreateEncryptKey(tk, jd.Group)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	jk := struct {
		ID  string `json:"id"`
		Alg string `json:"alg"`
		Key string `json:"key"`
	}{
		ID:  ek.ID,
		Alg: ek.Alg,
		Key: ek.Key,
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, jk)
}

// GetKey getting a single key
// @Summary getting a single key
// @Tags configs
// @Produce  n.n.
// @Param token as authentication header
// @Param id id of key
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/keys/{id} [post]
func (v *VaultHandler) GetKey(response http.ResponseWriter, request *http.Request) {
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	id := chi.URLParam(request, "id")
	ek, err := v.cl.GetEncryptKey(tk, id)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	jk := struct {
		ID  string `json:"id"`
		Alg string `json:"alg"`
		Key string `json:"key"`
	}{
		ID:  ek.ID,
		Alg: ek.Alg,
		Key: ek.Key,
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, jk)
}

// PostCrypt posting a crypt message, getting back the result, server side en/decryption
// @Summary  posting a crypt message, getting back the result, server side en/decryption
// @Tags configs
// @Accept  pem file
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/certificate [post]
func (v *VaultHandler) PostCrypt(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}

	var jd pmodel.Message
	err = json.NewDecoder(request.Body).Decode(&jd)
	if err != nil {
		httputils.Err(response, request, serror.InternalServerError(err))
		return
	}

	j, err := v.cl.CryptSS(tk, jd)
	if err != nil {
		httputils.Err(response, request, serror.InternalServerError(err))
		return
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, j)
}

// PostSign posting a message to sign, getting back the result, server side signing
// @Summary posting a message to sign, getting back the result, server side signing
// @Tags configs
// @Accept  pem file
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/certificate [post]
func (v *VaultHandler) PostSign(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}

	var jd pmodel.SignMessage
	err = json.NewDecoder(request.Body).Decode(&jd)
	if err != nil {
		httputils.Err(response, request, serror.InternalServerError(err))
		return
	}

	j, err := v.cl.SignSS(tk, &jd)
	if err != nil {
		httputils.Err(response, request, serror.InternalServerError(err))
		return
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, j)
}

// PostCheck posting a message to check the signature, getting back the result, server side sing checking
// @Summary posting a message to check the signature, getting back the result, server side sing checking
// @Tags configs
// @Accept  pem file
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/certificate [post]
func (v *VaultHandler) PostCheck(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}

	var jd pmodel.SignMessage
	err = json.NewDecoder(request.Body).Decode(&jd)
	if err != nil {
		httputils.Err(response, request, serror.InternalServerError(err))
		return
	}

	j, err := v.cl.CheckSS(tk, &jd)
	if err != nil {
		httputils.Err(response, request, serror.InternalServerError(err))
		return
	}

	render.Status(request, http.StatusOK)
	render.JSON(response, request, j)
}
