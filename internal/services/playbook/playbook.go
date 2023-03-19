package playbook

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/samber/do"
	log "github.com/willie68/micro-vault/internal/logging"

	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	cry "github.com/willie68/micro-vault/pkg/crypt"
)

// Playbook is a class which can play a playbook file for automated creation of groups and clients
type Playbook struct {
	stg  interfaces.Storage
	pm   *model.Playbook
	file string
}

// NewPlaybookFile creating a new playbook
func NewPlaybookFile(pf string) Playbook {
	return Playbook{
		stg:  do.MustInvokeNamed[interfaces.Storage](nil, interfaces.DoStorage),
		file: pf,
	}
}

// NewPlaybook creating a new playbook
func NewPlaybook(pm model.Playbook) Playbook {
	return Playbook{
		stg: do.MustInvokeNamed[interfaces.Storage](nil, interfaces.DoStorage),
		pm:  &pm,
	}
}

// Load initialize with a playbook file
func (p *Playbook) Load() error {
	pm, err := loadFromFile(p.file)
	if err != nil {
		return err
	}
	p.pm = pm
	return nil
}

// Play initialize with a playbook file
func (p *Playbook) Play() error {
	if p.pm == nil {
		return nil
	}
	for _, g := range p.pm.Groups {
		if !p.stg.HasGroup(g.Name) {
			_, err := p.stg.AddGroup(g)
			if err != nil {
				log.Logger.Errorf("error adding group %s: %v", g.Name, err)
				return err
			}
			log.Logger.Infof("adding group %s", g.Name)
		}
	}
	for _, c := range p.pm.Clients {
		if !p.stg.HasClient(c.Name) {
			if c.Key == "" {
				rsk, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return err
				}
				pem, err := cry.Prv2Pem(rsk)
				if err != nil {
					return err
				}
				c.Key = string(pem)
				log.Logger.Infof("creating new Pem for %s: \r\n%s", c.Name, c.Key)
			}

			if c.KID == "" {
				kid, err := cry.GetKIDOfPEM(c.Key)
				if err != nil {
					return err
				}
				c.KID = kid
			}
			_, err := p.stg.AddClient(c)
			if err != nil {
				log.Logger.Errorf("error adding client %s: %v", c.Name, err)
				return err
			}
			log.Logger.Infof("adding client %s", c.Name)
		}
	}
	return nil
}

// Export exporting the actual groups and clients to a playbook file
func (p *Playbook) Export(pf string) error {
	pb := model.Playbook{
		Groups:  make([]model.Group, 0),
		Clients: make([]model.Client, 0),
	}
	gs, err := p.stg.GetGroups()
	if err != nil {
		return err
	}
	pb.Groups = gs
	p.stg.ListClients(func(g model.Client) bool {
		pb.Clients = append(pb.Clients, g)
		return true
	})
	file, err := os.OpenFile(pf, os.O_CREATE, os.ModePerm)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	err = encoder.Encode(pb)
	return err
}

func loadFromFile(f string) (*model.Playbook, error) {
	if _, err := os.Stat(f); err != nil {
		return nil, err
	}
	if !strings.HasSuffix(f, ".json") {
		return nil, errors.New("file must be a valid json file")
	}
	data, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("can't load playbook file: %v", err)
	}
	var pb model.Playbook
	err = json.Unmarshal(data, &pb)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal config file: %v", err)
	}

	return &pb, nil
}
