// Package main this is the entry point into the service
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/willie68/micro-vault/internal/api"
	"github.com/willie68/micro-vault/internal/apiv1"
	"github.com/willie68/micro-vault/internal/auth"
	"github.com/willie68/micro-vault/internal/health"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/serror"
	"github.com/willie68/micro-vault/internal/services/admin"
	"github.com/willie68/micro-vault/internal/services/clients"
	"github.com/willie68/micro-vault/internal/services/groups"
	"github.com/willie68/micro-vault/internal/services/keyman"
	"github.com/willie68/micro-vault/internal/services/playbook"
	"github.com/willie68/micro-vault/internal/services/storage"
	"github.com/willie68/micro-vault/internal/utils/httputils"
	"github.com/willie68/micro-vault/pkg/web"

	"github.com/opentracing/opentracing-go"
	"github.com/uber/jaeger-client-go"
	config "github.com/willie68/micro-vault/internal/config"

	jaegercfg "github.com/uber/jaeger-client-go/config"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httptracer"
	"github.com/go-chi/render"
	"github.com/willie68/micro-vault/internal/crypt"
	log "github.com/willie68/micro-vault/internal/logging"

	flag "github.com/spf13/pflag"
)

var (
	port          int
	sslport       int
	serviceURL    string
	ssl           bool
	configFile    string
	serviceConfig config.Config
	tracer        opentracing.Tracer
	sslsrv        *http.Server
	srv           *http.Server
	pbf           string
	pbexport      string
)

func init() {
	// variables for parameter override
	ssl = false
	log.Logger.Info("init service")
	flag.IntVarP(&port, "port", "p", 0, "port of the http server.")
	flag.IntVarP(&sslport, "sslport", "t", 0, "port of the https server.")
	flag.StringVarP(&configFile, "config", "c", config.File, "this is the path and filename to the config file")
	flag.StringVarP(&serviceURL, "serviceURL", "u", "", "service url from outside")
	flag.StringVarP(&pbf, "playbook", "b", "", "playbook file for automated init")
	flag.StringVarP(&pbexport, "export", "e", "", "export playbook file for backup")
}

func apiRoutes() (*chi.Mux, error) {
	log.Logger.Infof("baseurl : %s", apiv1.BaseURL)
	router := chi.NewRouter()
	setDefaultHandler(router)

	// jwt is activated, register the Authenticator and Validator
	if strings.EqualFold(serviceConfig.Auth.Type, "jwt") {
		err := setJWTHandler(router)
		if err != nil {
			return nil, err
		}
	}

	// building the routes
	router.Route("/", func(r chi.Router) {
		r.Mount(apiv1.NewVaultHandler().Routes())
		r.Mount(apiv1.NewAdminHandler().Routes())
		r.Mount("/", health.Routes())
		if serviceConfig.Metrics.Enable {
			r.Mount("/metrics", promhttp.Handler())
		}
	})
	// adding a file server with web client asserts
	httputils.FileServer(router, "/client", http.FS(web.WebClientAssets))
	return router, nil
}

func setJWTHandler(router *chi.Mux) error {
	jwtConfig, err := auth.ParseJWTConfig(serviceConfig.Auth)
	if err != nil {
		return err
	}
	log.Logger.Infof("jwt config: %v", jwtConfig)
	jwtAuth := auth.JWTAuth{
		Config: jwtConfig,
	}
	router.Use(
		auth.Verifier(&jwtAuth),
		auth.Authenticator,
	)
	return nil
}

func setDefaultHandler(router *chi.Mux) {
	router.Use(
		render.SetContentType(render.ContentTypeJSON),
		middleware.Logger,
		//middleware.DefaultCompress,
		middleware.Recoverer,
		cors.Handler(cors.Options{
			// AllowedOrigins: []string{"https://foo.com"}, // Use this to allow specific origin hosts
			AllowedOrigins: []string{"*"},
			// AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-mcs-username", "X-mcs-password", "X-mcs-profile"},
			ExposedHeaders:   []string{"Link"},
			AllowCredentials: true,
			MaxAge:           300, // Maximum value not ignored by any of major browsers
		}),
		httptracer.Tracer(tracer, httptracer.Config{
			ServiceName:    config.Servicename,
			ServiceVersion: "V" + apiv1.APIVersion,
			SampleRate:     1,
			SkipFunc: func(r *http.Request) bool {
				return false
				//return r.URL.Path == "/livez"
			},
			Tags: map[string]any{
				"_dd.measured": 1, // datadog, turn on metrics for http.request stats
				// "_dd1.sr.eausr": 1, // datadog, event sample rate
			},
		}),
	)
	if serviceConfig.Metrics.Enable {
		router.Use(
			api.MetricsHandler(api.MetricsConfig{
				SkipFunc: func(r *http.Request) bool {
					return false
				},
			}),
		)
	}
}

func healthRoutes() *chi.Mux {
	router := chi.NewRouter()
	router.Use(
		render.SetContentType(render.ContentTypeJSON),
		middleware.Logger,
		//middleware.DefaultCompress,
		middleware.Recoverer,
		httptracer.Tracer(tracer, httptracer.Config{
			ServiceName:    config.Servicename,
			ServiceVersion: "V" + apiv1.APIVersion,
			SampleRate:     1,
			SkipFunc: func(r *http.Request) bool {
				return false
			},
			Tags: map[string]any{
				"_dd.measured": 1, // datadog, turn on metrics for http.request stats
				// "_dd1.sr.eausr": 1, // datadog, event sample rate
			},
		}),
	)
	if serviceConfig.Metrics.Enable {
		router.Use(
			api.MetricsHandler(api.MetricsConfig{
				SkipFunc: func(r *http.Request) bool {
					return false
				},
			}),
		)
	}

	router.Route("/", func(r chi.Router) {
		r.Mount("/", health.Routes())
		if serviceConfig.Metrics.Enable {
			r.Mount(api.MetricsEndpoint, promhttp.Handler())
		}
	})
	return router
}

// @title GoMicro service API
// @version 1.0
// @description The GoMicro service is a template for microservices written in go.
// @BasePath /api/v1
// @in header
func main() {
	configFolder, err := config.GetDefaultConfigFolder()
	if err != nil {
		panic("can't get config folder")
	}

	flag.Parse()

	log.Logger.Infof("starting server, config folder: %s", configFolder)
	defer log.Logger.Close()

	serror.Service = config.Servicename
	if configFile == "" {
		configFile, err = getDefaultConfigfile()
		if err != nil {
			log.Logger.Errorf("error getting default config file: %v", err)
			panic("error getting default config file")
		}
	}

	config.File = configFile
	log.Logger.Infof("using config file: %s", configFile)

	if err := config.Load(); err != nil {
		log.Logger.Alertf("can't load config file: %s", err.Error())
		panic("can't load config file")
	}

	serviceConfig = config.Get()
	initConfig()
	initLogging()

	if err := initServices(serviceConfig.Service); err != nil {
		log.Logger.Alertf("error creating memory storage: %v", err)
		panic("error creating memory storage")
	}

	if pbexport != "" {
		log.Logger.Infof("export playbook to file: %s", pbexport)
		pb := playbook.NewPlaybook(model.Playbook{})
		err := pb.Export(pbexport)
		if err != nil {
			log.Logger.Errorf("error exporting playbook: %v", err)
		}
		os.Exit(1)
	}
	log.Logger.Info("service is starting")

	var closer io.Closer
	tracer, closer = initJaeger(config.Servicename, serviceConfig.OpenTracing)
	opentracing.SetGlobalTracer(tracer)
	defer closer.Close()

	healthCheckConfig := health.CheckConfig(serviceConfig.HealthCheck)

	health.InitHealthSystem(healthCheckConfig, tracer)

	if serviceConfig.Sslport > 0 {
		ssl = true
		log.Logger.Info("ssl active")
	}

	log.Logger.Infof("ssl: %t", ssl)
	log.Logger.Infof("serviceURL: %s", serviceConfig.ServiceURL)
	log.Logger.Infof("%s api routes", config.Servicename)
	router, err := apiRoutes()
	if err != nil {
		errstr := fmt.Sprintf("could not create api routes. %s", err.Error())
		log.Logger.Alertf(errstr)
		panic(errstr)
	}
	walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		log.Logger.Infof("%s %s", method, route)
		return nil
	}

	if err := chi.Walk(router, walkFunc); err != nil {
		log.Logger.Alertf("could not walk api routes. %s", err.Error())
	}
	log.Logger.Info("health api routes")
	healthRouter := healthRoutes()
	if err := chi.Walk(healthRouter, walkFunc); err != nil {
		log.Logger.Alertf("could not walk health routes. %s", err.Error())
	}

	if ssl {
		startHTTPSServer(router)
		startHTTPServer(healthRouter)
	} else {
		startHTTPServer(router)
	}

	log.Logger.Info("waiting for clients")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	shutdownServers()
	log.Logger.Info("finished")

	os.Exit(0)
}

func shutdownServers() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Logger.Errorf("shutdown http server error: %v", err)
	}
	if ssl {
		if err := sslsrv.Shutdown(ctx); err != nil {
			log.Logger.Errorf("shutdown https server error: %v", err)
		}
	}
}

func startHTTPSServer(router *chi.Mux) {
	gc := crypt.GenerateCertificate{
		Organization: "MCS",
		Host:         "127.0.0.1",
		ValidFor:     10 * 365 * 24 * time.Hour,
		IsCA:         false,
		EcdsaCurve:   "P384",
		Ed25519Key:   false,
	}
	tlsConfig, err := gc.GenerateTLSConfig()
	if err != nil {
		log.Logger.Alertf("could not create tls config. %s", err.Error())
	}
	sslsrv = &http.Server{
		Addr:         "0.0.0.0:" + strconv.Itoa(serviceConfig.Sslport),
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      router,
		TLSConfig:    tlsConfig,
	}
	go func() {
		log.Logger.Infof("starting https server on address: %s", sslsrv.Addr)
		if err := sslsrv.ListenAndServeTLS("", ""); err != nil {
			log.Logger.Alertf("error starting server: %s", err.Error())
		}
	}()
}

func startHTTPServer(router *chi.Mux) {
	// own http server for the healthchecks
	srv = &http.Server{
		Addr:         "0.0.0.0:" + strconv.Itoa(serviceConfig.Port),
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      router,
	}
	go func() {
		log.Logger.Infof("starting http server on address: %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Logger.Alertf("error starting server: %s", err.Error())
		}
	}()
}

func getDefaultConfigfile() (string, error) {
	configFolder, err := config.GetDefaultConfigFolder()
	if err != nil {
		return "", errors.Wrap(err, "can't load config file")
	}
	configFolder = filepath.Join(configFolder, "service")
	err = os.MkdirAll(configFolder, os.ModePerm)
	if err != nil {
		return "", errors.Wrap(err, "can't load config file")
	}
	return filepath.Join(configFolder, "service.yaml"), nil
}

// initLogging initialize the logging, especially the gelf logger
func initLogging() {
	log.Logger.SetLevel(serviceConfig.Logging.Level)
	var err error
	serviceConfig.Logging.Filename, err = config.ReplaceConfigdir(serviceConfig.Logging.Filename)
	if err != nil {
		log.Logger.Errorf("error on config dir: %v", err)
	}
	log.Logger.GelfURL = serviceConfig.Logging.Gelfurl
	log.Logger.GelfPort = serviceConfig.Logging.Gelfport
	log.Logger.Init()
}

// initConfig override the configuration from the service.yaml with the given commandline parameters
func initConfig() {
	if port > 0 {
		serviceConfig.Port = port
	}
	if sslport > 0 {
		serviceConfig.Sslport = sslport
	}
	if serviceURL != "" {
		serviceConfig.ServiceURL = serviceURL
	}

	if pbf != "" {
		serviceConfig.Service.Playbook = pbf
	}
	serviceConfig.Provide()
}

// initJaeger initialize the jaeger (opentracing) component
func initJaeger(servicename string, cnfg config.OpenTracing) (opentracing.Tracer, io.Closer) {
	cfg := jaegercfg.Configuration{
		ServiceName: servicename,
		Sampler: &jaegercfg.SamplerConfig{
			Type:  "const",
			Param: 1,
		},
		Reporter: &jaegercfg.ReporterConfig{
			LogSpans:           true,
			LocalAgentHostPort: cnfg.Host,
			CollectorEndpoint:  cnfg.Endpoint,
		},
	}
	if (cnfg.Endpoint == "") && (cnfg.Host == "") {
		cfg.Disabled = true
	}
	tracer, closer, err := cfg.NewTracer(jaegercfg.Logger(jaeger.StdLogger))
	if err != nil {
		panic(fmt.Sprintf("ERROR: cannot init Jaeger: %v\n", err))
	}
	return tracer, closer
}

func initServices(c config.Service) error {
	_, err := storage.NewStorage(c.Storage)
	if err != nil {
		return err
	}

	_, err = keyman.NewKeyman()
	if err != nil {
		return err
	}

	_, err = clients.NewClients()
	if err != nil {
		return err
	}

	_, err = groups.NewGroups()
	if err != nil {
		return err
	}

	_, err = admin.NewAdmin()
	if err != nil {
		return err
	}

	if c.Playbook != "" {
		pb := playbook.NewPlaybookFile(c.Playbook)
		err := pb.Load()
		if err != nil {
			return err
		}
		err = pb.Play()
		return err
	}
	return nil
}
