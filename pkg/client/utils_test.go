package client

import (
	"fmt"

	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/apiv1"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/health"
	"github.com/willie68/micro-vault/internal/services"
	"github.com/willie68/micro-vault/internal/services/shttp"
)

var (
	srvStarted bool
	sh         *shttp.SHttp
	cfg        config.Config
)

func StartServer() {
	if sh == nil {

		fmt.Println("starting server")
		// loading the config file
		config.File = "../../testdata/service_local.yaml"
		err := config.Load()
		if err != nil {
			panic("can't load local config")
		}

		cfg = config.Get()
		cfg.Service.Playbook = "../../testdata/playbook.json"
		cfg.Provide()
		if err := services.InitServices(cfg); err != nil {
			panic("error creating services")
		}

		healthCheckConfig := health.CheckConfig(cfg.HealthCheck)
		health.InitHealthSystem(healthCheckConfig, nil)

		s := do.MustInvokeNamed[shttp.SHttp](nil, shttp.DoSHTTP)
		sh = &s
	}
	if !sh.Started {
		router, err := apiv1.APIRoutes(cfg, nil)
		if err != nil {
			errstr := fmt.Sprintf("could not create api routes. %s", err.Error())
			panic(errstr)
		}

		healthRouter := apiv1.HealthRoutes(cfg, nil)
		sh.StartServers(router, healthRouter)
	}
}
