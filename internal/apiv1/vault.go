package apiv1

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/willie68/micro-vault/internal/serror"
	"github.com/willie68/micro-vault/internal/utils/httputils"
)

// VaultRoutes getting all routes for the config endpoint
func VaultRoutes() (string, *chi.Mux) {
	router := chi.NewRouter()
	router.Post("/login", PostLogin)
	return BaseURL + vaultSubpath, router
}

// PostLogin login a client to the vault service
// @Summary login a client to the vault service
// @Tags configs
// @Accept  json
// @Produce  json
// @Param Accesskey, Secret as strings for login
// @Param payload body string true "Add store"
// @Success 201 {object} token for further processing
// @Failure 400 {object} serror.Serr "client error information as json"
// @Failure 500 {object} serror.Serr "server error information as json"
// @Router /vault/login [post]
func PostLogin(response http.ResponseWriter, request *http.Request) {
	up := struct {
		AccessKey string `json:"accesskey"`
		Secret    string `json:"secret"`
	}{}
	err := json.NewDecoder(request.Body).Decode(&up)
	if err != nil {
		httputils.Err(response, request, serror.InternalServerError(err))
		return
	}

	render.Status(request, http.StatusOK)
	render.JSON(response, request, up)
}
