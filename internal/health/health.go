package health

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/opentracing/opentracing-go"
	log "github.com/willie68/micro-vault/internal/logging"
)

var myhealthy bool

// check This is the healtchcheck you will have to provide
func check(_ opentracing.Tracer) (bool, string) {
	// TODO implement here your healthcheck.
	myhealthy = !myhealthy
	message := ""
	if myhealthy {
		log.Logger.Info("healthy")
	} else {
		log.Logger.Info("not healthy")
		message = "ungesund"
	}
	return myhealthy, message
}

// ##### template internal functions for processing the healthchecks #####
var message string
var readyz bool
var lastChecked time.Time
var period int

// CheckConfig configuration for the healthcheck system
type CheckConfig struct {
	Period int
}

// Msg a health message
type Msg struct {
	Message   string `json:"message"`
	LastCheck string `json:"lastCheck,omitempty"`
}

// InitHealthSystem initialize the complete health system
func InitHealthSystem(config CheckConfig, tracer opentracing.Tracer) {
	period = config.Period
	log.Logger.Infof("healthcheck starting with period: %d seconds", period)
	message = "service starting"
	readyz = false
	doCheck(tracer)
	go func() {
		background := time.NewTicker(time.Second * time.Duration(period))
		for range background.C {
			doCheck(tracer)
		}
	}()
}

// doCheck internal function to process the health check
func doCheck(tracer opentracing.Tracer) {
	var msg string
	readyz, msg = check(tracer)
	if !readyz {
		message = msg
	} else {
		message = ""
	}
	lastChecked = time.Now()
}

// Routes getting all routes for the health endpoint
func Routes() *chi.Mux {
	router := chi.NewRouter()
	router.Get("/livez", GetLivenessEndpoint)
	router.Get("/readyz", GetReadinessEndpoint)
	router.Head("/livez", HeadLivenessEndpoint)
	router.Head("/readyz", HeadReadinessEndpoint)
	return router
}

// GetLivenessEndpoint liveness probe
func GetLivenessEndpoint(response http.ResponseWriter, req *http.Request) {
	render.Status(req, http.StatusOK)
	render.JSON(response, req, Msg{
		Message: "service started",
	})
}

// HeadLivenessEndpoint liveness probe
func HeadLivenessEndpoint(response http.ResponseWriter, req *http.Request) {
	render.Status(req, http.StatusOK)
	render.NoContent(response, req)
}

// GetReadinessEndpoint is this service ready for taking requests, e.g. formerly known as health checksfunc GetReadinessEndpoint(response http.ResponseWriter, req *http.Request) {
func GetReadinessEndpoint(response http.ResponseWriter, req *http.Request) {
	checkHealthCheckTimer()
	if readyz {
		render.Status(req, http.StatusOK)
		render.JSON(response, req, Msg{
			Message:   "service up and running",
			LastCheck: lastChecked.String(),
		})
	} else {
		render.Status(req, http.StatusServiceUnavailable)
		render.JSON(response, req, Msg{
			Message:   fmt.Sprintf("service is unavailable: %s", message),
			LastCheck: lastChecked.String(),
		})
	}
}

// HeadReadinessEndpoint is this service ready for taking requests, e.g. formaly known as health checks
func HeadReadinessEndpoint(response http.ResponseWriter, req *http.Request) {
	checkHealthCheckTimer()
	if readyz {
		render.Status(req, http.StatusOK)
	} else {
		render.Status(req, http.StatusServiceUnavailable)
	}
	render.NoContent(response, req)
}

// checking if the health system (namly the timer task) is working or stopped
func checkHealthCheckTimer() {
	t := time.Now()
	if t.Sub(lastChecked) > (time.Second * time.Duration(2*period)) {
		readyz = false
		message = "health check not running"
		if t.Sub(lastChecked) > (time.Second * time.Duration(4*period)) {
			log.Logger.Error("panic: health check is not running anymore")
			panic("panic: health check is not running anymore")
		}
	}
}

// sendMessage sending a span message to tracer
func sendMessage(tracer opentracing.Tracer, message string) {
	span := tracer.StartSpan("say-hello")
	println(message)
	span.Finish()
}
