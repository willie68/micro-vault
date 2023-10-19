package apiv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/api"
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
		cl: do.MustInvoke[clients.Clients](nil),
	}
}

// Routes getting all routes for the config endpoint
func (v *VaultHandler) Routes() (string, *chi.Mux) {
	router := chi.NewRouter()
	router.Post("/clients/certificate", v.PostCert)
	router.Get("/clients/certificate/{name}", v.GetCertByName)
	router.Post("/groups/keys", v.PostKeys)
	router.Get("/groups/keys/{id}", v.GetKey)
	router.Post("/groups/crypt", v.PostCrypt)
	router.Post("/signature/sign", v.PostSign)
	router.Post("/signature/check", v.PostCheck)
	router.Post("/msg", v.PostMsg)
	router.Get("/msg/{id}", v.GetMsg)
	router.Delete("/msg/{id}", v.DeleteMsg)
	return BaseURL + vaultSubpath, router
}

// PostCert posting a certificate request to this mv service, returning a signed certificate
// @Summary posting a certificate request to this mv service, returning a signed certificate
// @Tags configs
// @Accept  pem file
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/certificate/{name} [post]
func (v *VaultHandler) PostCert(response http.ResponseWriter, request *http.Request) {
	var err error
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	pb := new(bytes.Buffer)
	_, err = io.Copy(pb, request.Body)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	ct, err := v.cl.CreateCertificate(tk, string(pb.Bytes()))
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	response.Header().Add("Content-Type", "application/x-pem-file")
	response.WriteHeader(http.StatusCreated)
	_, err = response.Write([]byte(ct))
	if err != nil {
		logger.Errorf("error writing PEM: %v", err)
	}
}

// GetCertByName getting the public key of a client certificate for the named client
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
func (v *VaultHandler) GetCertByName(response http.ResponseWriter, request *http.Request) {
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
	ct, err := v.cl.GetPublicKey(tk, name)
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
	render.Status(request, http.StatusCreated)
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

// PostMsg posting message to be stored securly for group/client
// @Summary posting message to be stored securly for group/client
// @Tags configs
// @Accept  pem file
// @Produce  n.n.
// @Param token as authentication header
// @Param payload body pem file
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/keys [post]
func (v *VaultHandler) PostMsg(response http.ResponseWriter, request *http.Request) {
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	var msg pmodel.Message
	err = json.NewDecoder(request.Body).Decode(&msg)
	if err != nil {
		httputils.Err(response, request, serror.InternalServerError(err))
		return
	}

	id, err := v.cl.StoreData(tk, msg)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	jk := struct {
		ID string `json:"id"`
	}{
		ID: id,
	}
	render.Status(request, http.StatusCreated)
	render.JSON(response, request, jk)
}

// GetMsg getting a single message, if allowed
// @Summary getting a single message, if allowed
// @Tags configs
// @Produce  n.n.
// @Param token as authentication header
// @Param id id of key
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/keys/{id} [post]
func (v *VaultHandler) GetMsg(response http.ResponseWriter, request *http.Request) {
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	id := chi.URLParam(request, "id")
	msg, err := v.cl.GetData(tk, id)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	render.Status(request, http.StatusOK)
	render.JSON(response, request, msg)
}

// DeleteMsg deleting a single message, if allowed
// @Summary deleting a single message, if allowed
// @Tags configs
// @Produce  n.n.
// @Param token as authentication header
// @Param id id of key
// @Success 200 {object} nothing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/keys/{id} [post]
func (v *VaultHandler) DeleteMsg(response http.ResponseWriter, request *http.Request) {
	tk, err := token(request)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	id := chi.URLParam(request, "id")
	ok, err := v.cl.DeleteData(tk, id)
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusBadRequest))
		return
	}
	if !ok {
		render.Status(request, http.StatusBadRequest)
		return
	}
	render.Status(request, http.StatusOK)
}
