package apiv1

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/api"
	"github.com/willie68/micro-vault/internal/services/keyman"
)

// JWKSHandler handler for handling REST calls for jwks
type JWKSHandler struct {
	kmn keyman.Keyman
}

// NewJWKSHandler returning a new REST API Handler for jwks
func NewJWKSHandler() api.Handler {
	return &JWKSHandler{
		kmn: do.MustInvoke[keyman.Keyman](nil),
	}
}

// Routes getting all routes for the config endpoint
func (j *JWKSHandler) Routes() (string, *chi.Mux) {
	router := chi.NewRouter()
	router.Get("/jwks.json", j.GetJWKS)
	return jwksSubpath, router
}

// GetJWKS returning all possible public certificates of this service
func (j *JWKSHandler) GetJWKS(response http.ResponseWriter, request *http.Request) {
	render.Status(request, http.StatusOK)
	render.JSON(response, request, j.kmn.JWKS())
}
