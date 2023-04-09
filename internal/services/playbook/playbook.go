package playbook

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

	err := p.addClients()
	if err != nil {
		return err
	}

	err = p.addGroups()
	if err != nil {
		return err
	}

	err = p.addKeys()
	if err != nil {
		return err
	}
	return nil
}

func (p *Playbook) addClients() error {
	for _, c := range p.pm.Clients {
		if p.stg.HasGroup(c.Name) || p.stg.HasClient(c.Name) {
			log.Logger.Errorf("can't import client \"%s\", client or group already exists.", c.Name)
			continue
		}
		err := p.ensureAddClient(c)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Playbook) ensureAddClient(c model.Client) (err error) {
	if c.Key == "" {
		log.Logger.Infof("creating new Pem for %s: \r\n%s", c.Name, c.Key)
		c.Key, err = p.generateNewKeyPem()
		if err != nil {
			return err
		}
	}

	if c.KID == "" {
		c.KID, err = cry.GetKIDOfPEM(c.Key)
		if err != nil {
			return err
		}
	}

	salt, err := cry.GenerateSalt()
	if err != nil {
		return err
	}
	secret, err := hex.DecodeString(c.Secret)
	if err != nil {
		return err
	}
	hash := cry.HashSecret(secret, salt)
	cl := model.Client{
		Name:      c.Name,
		Salt:      hex.EncodeToString(salt),
		AccessKey: c.AccessKey,
		Hash:      hash,
		Groups:    c.Groups,
		Key:       c.Key,
		KID:       c.KID,
	}
	_, err = p.stg.AddClient(cl)
	if err != nil {
		log.Logger.Errorf("error adding client %s: %v", c.Name, err)
		return err
	}
	g := model.Group{
		Name: c.Name,
	}
	_, err = p.stg.AddGroup(g)
	if err != nil {
		log.Logger.Errorf("error adding group for client %s: %v", c.Name, err)
		return err
	}
	log.Logger.Infof("adding client %s", c.Name)
	return nil
}

func (p *Playbook) generateNewKeyPem() (string, error) {
	rsk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	pem, err := cry.Prv2Pem(rsk)
	if err != nil {
		return "", err
	}
	return string(pem), nil
}

func (p *Playbook) addGroups() error {
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
	return nil
}

func (p *Playbook) addKeys() error {
	for _, k := range p.pm.Keys {
		if !p.stg.HasEncryptKey(k.ID) {
			err := p.stg.StoreEncryptKey(k)
			if err != nil {
				log.Logger.Errorf("error adding key %s: %v", k.ID, err)
				return err
			}
			log.Logger.Infof("adding key %s", k.ID)
		}
	}
	return nil
}

// Export exporting the actual groups and clients to a playbook file
func (p *Playbook) Export(pf string) error {
	pb := model.Playbook{
		Groups:  make([]model.Group, 0),
		Clients: make([]model.Client, 0),
		Keys:    make([]model.EncryptKey, 0),
	}
	err := p.stg.ListClients(func(c model.Client) bool {
		pb.Clients = append(pb.Clients, c)
		return true
	})
	if err != nil {
		return err
	}

	gs, err := p.stg.GetGroups()
	if err != nil {
		return err
	}
	for _, g := range gs {
		if !p.stg.HasClient(g.Name) {
			pb.Groups = append(pb.Groups, g)
		}
	}

	err = p.stg.ListEncryptKeys(0, math.MaxInt64, func(g model.EncryptKey) bool {
		pb.Keys = append(pb.Keys, g)
		return true
	})
	if err != nil {
		return err
	}

	file, err := os.Create(pf)
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
