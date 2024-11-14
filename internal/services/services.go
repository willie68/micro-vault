package services

import (
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/logging"
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
	logger = logging.New().WithName("services")
)

// InitServices initialise the service system
func InitServices(cfg config.Config) error {
	logger.Debug("initialise services")
	err := InitHelperServices(cfg)

	_, err = keyman.NewKeyman(cfg.PrivateKey)
	if err != nil {
		return err
	}

	_, err = keyman.NewCAService(cfg.CACert)
	if err != nil {
		return err
	}

	_, err = storage.NewStorage(cfg.Storage)
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

	if cfg.Playbook != "" {
		pb := playbook.NewPlaybookFile(cfg.Playbook)
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
	_, err = health.NewHealthSystem(cfg.HealthSystem)
	return err
}

// InitRESTService initialise REST Services
func InitRESTService(cfg config.Config) error {
	_, err := shttp.NewSHttp(cfg.HTTP)
	return err
}
