package apiv1

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/api"
	"github.com/willie68/micro-vault/internal/serror"
	"github.com/willie68/micro-vault/internal/services/keyman"
	"github.com/willie68/micro-vault/internal/utils/httputils"
)

// CACert handler for handling REST calls for jwks
type CACert struct {
	cas keyman.CAService
}

// NewCACertHandler returning a new REST API Handler for jwks
func NewCACertHandler() api.Handler {
	return &CACert{
		cas: do.MustInvokeNamed[keyman.CAService](nil, keyman.DoCAService),
	}
}

// Routes getting all routes for the config endpoint
func (c *CACert) Routes() (string, *chi.Mux) {
	router := chi.NewRouter()
	router.Get("/cacert", c.GetCACert)
	return caSubpath, router
}

// GetCACert returning all possible public certificates of this service
func (c *CACert) GetCACert(response http.ResponseWriter, request *http.Request) {
	crt, err := c.cas.X509Cert()
	if err != nil {
		httputils.Err(response, request, serror.Wrapc(err, http.StatusInternalServerError))
		return
	}
	response.Header().Add("Content-Disposition", `attachment; filename="certificate.pem"`)
	response.Header().Set("Content-Type", "application/x-pem-file")
	response.WriteHeader(http.StatusOK)
	response.Write([]byte(crt))
}
