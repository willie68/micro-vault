package services

import (
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/services/admin"
	"github.com/willie68/micro-vault/internal/services/clients"
	"github.com/willie68/micro-vault/internal/services/groups"
	"github.com/willie68/micro-vault/internal/services/keyman"
	"github.com/willie68/micro-vault/internal/services/playbook"
	"github.com/willie68/micro-vault/internal/services/shttp"
	"github.com/willie68/micro-vault/internal/services/storage"
)

// InitServices initialise the service system
func InitServices(cfg config.Config) error {
	c := cfg.Service

	_, err := keyman.NewKeyman()
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

	_, err = shttp.NewSHttp(cfg.Service.HTTP)
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
