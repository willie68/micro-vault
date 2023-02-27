package api

import "github.com/go-chi/chi/v5"

// MetricsEndpoint endpoint subpath  for metrics
const MetricsEndpoint = "/metrics"

// Handler a http REST interface handler
type Handler interface {
	// Routes get the routes
	Routes() (string, *chi.Mux)
}
