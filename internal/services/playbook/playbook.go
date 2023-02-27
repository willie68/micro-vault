package playbook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/samber/do"
	log "github.com/willie68/micro-vault/internal/logging"

	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
)

// Playbook is a class which can play a playbook file for automated creation of groups and clients
type Playbook struct {
	stg  interfaces.Storage
	file string
}

// NewPlaybook creating a new playbook
func NewPlaybook(pf string) Playbook {
	return Playbook{
		stg:  do.MustInvokeNamed[interfaces.Storage](nil, "storage"),
		file: pf,
	}
}

// Play initialize with a playbook file
func (p *Playbook) Play() error {
	pb, err := loadFromFile(p.file)
	if err != nil {
		return err
	}
	for _, g := range pb.Groups {
		_, err := p.stg.AddGroup(g)
		if err != nil {
			log.Logger.Errorf("error adding group %s: %v", g.Name, err)
			return err
		} else {
			log.Logger.Infof("adding group %s", g.Name)
		}
	}
	for _, c := range pb.Clients {
		_, err := p.stg.AddClient(c)
		if err != nil {
			log.Logger.Errorf("error adding client %s: %v", c.Name, err)
			return err
		} else {
			log.Logger.Infof("adding client %s", c.Name)
		}
	}
	return nil
}

func loadFromFile(f string) (*model.Playbook, error) {
	if _, err := os.Stat(f); err != nil {
		return nil, err
	}
	if !strings.HasSuffix(f, ".json") {
		return nil, errors.New("file must be a valid json file")
	}
	data, err := ioutil.ReadFile(f)
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
