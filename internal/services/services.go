package services

import (
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/services/admin"
	"github.com/willie68/micro-vault/internal/services/clients"
	"github.com/willie68/micro-vault/internal/services/groups"
	"github.com/willie68/micro-vault/internal/services/health"
	"github.com/willie68/micro-vault/internal/services/keyman"
	"github.com/willie68/micro-vault/internal/services/playbook"
	"github.com/willie68/micro-vault/internal/services/shttp"
	"github.com/willie68/micro-vault/internal/services/storage"
)

var (
	healthService *health.SHealth
)

// InitServices initialise the service system
func InitServices(cfg config.Config) error {
	err := InitHelperServices(cfg)

	c := cfg.Service

	_, err = keyman.NewKeyman()
	if err != nil {
		return err
	}

	_, err = keyman.NewCAService()
	if err != nil {
		return err
	}

	_, err = storage.NewStorage(c.Storage)
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
		if err != nil {
			return err
		}
	}

	return InitRESTService(cfg)
}

// InitHelperServices initialise the helper services like Healthsystem
func InitHelperServices(cfg config.Config) error {
	var err error
	healthService, err = health.NewHealthSystem(cfg.Service.HealthSystem)
	if err != nil {
		return err
	}
	return nil
}

// InitRESTService initialise REST Services
func InitRESTService(cfg config.Config) error {
	_, err := shttp.NewSHttp(cfg.Service.HTTP)
	if err != nil {
		return err
	}
	return nil
}
