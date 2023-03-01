package admin

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services"
	"github.com/willie68/micro-vault/internal/services/clients"
	"github.com/willie68/micro-vault/internal/services/groups"
	"github.com/willie68/micro-vault/internal/services/playbook"
)

// DoAdmin injection name
const DoAdmin = "admin"

// Admin admin service business logic
type Admin struct {
	rootusr string
	pwdhash string
	stg     interfaces.Storage
	cls     clients.Clients
	grs     groups.Groups
}

// NewAdmin creates a new admin service
func NewAdmin() (Admin, error) {
	cfg := do.MustInvokeNamed[config.Config](nil, config.DoServiceConfig)
	a := Admin{
		rootusr: cfg.Service.Rootuser,
		pwdhash: hash([]byte(cfg.Service.Rootpwd)),
		stg:     do.MustInvokeNamed[interfaces.Storage](nil, interfaces.DoStorage),
		cls:     do.MustInvokeNamed[clients.Clients](nil, clients.DoClients),
		grs:     do.MustInvokeNamed[groups.Groups](nil, groups.DoGroups),
	}
	err := a.Init()
	if err != nil {
		return Admin{}, err
	}
	do.ProvideNamedValue[Admin](nil, DoAdmin, a)
	return a, err
}

// Init initialize admin service
func (a *Admin) Init() error {
	return nil
}

// LoginUP logging in a admin account
func (a *Admin) LoginUP(u string, p []byte) (string, error) {
	if !strings.EqualFold(u, a.rootusr) || hash(p) != a.pwdhash {
		return "", services.ErrLoginFailed
	}

	t := jwt.New()
	t.Set(jwt.AudienceKey, "microvault-admins")
	t.Set(jwt.IssuedAtKey, time.Now())
	t.Set(jwt.ExpirationKey, time.Now().Add(5*time.Minute))
	t.Set("roles", []string{"mv-admin"})

	// Signing a token (using raw rsa.PrivateKey)
	signed, err := jwt.Sign(t, jwa.RS256, a.cls.Key())
	if err != nil {
		log.Printf("failed to sign token: %s", err)
		return "", err
	}
	return string(signed), nil
}

// Playbook plays the playbook
func (a *Admin) Playbook(tk string, pm model.Playbook) error {
	ok, err := a.checkTk(tk)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("token error")
	}
	pb := playbook.NewPlaybook(pm)
	return pb.Play()
}

// Groups getting all defined groups
func (a *Admin) Groups(tk string) ([]model.Group, error) {
	ok, err := a.checkTk(tk)
	if err != nil {
		return []model.Group{}, err
	}
	if !ok {
		return []model.Group{}, errors.New("token error")
	}
	return a.stg.GetGroups()
}

// Clients get all defined clients
func (a *Admin) Clients(tk string) ([]model.Client, error) {
	ok, err := a.checkTk(tk)
	if err != nil {
		return []model.Client{}, err
	}
	if !ok {
		return []model.Client{}, errors.New("token error")
	}
	cl := make([]model.Client, 0)
	err = a.stg.ListClients(func(c model.Client) bool {
		cl = append(cl, c)
		return true
	})
	return cl, err
}

func (a *Admin) checkTk(tk string) (bool, error) {
	token, err := jwt.Parse([]byte(tk), jwt.WithVerify(jwa.RS256, a.cls.PublicKey()))
	if err != nil {
		return false, err
	}
	roles := token.PrivateClaims()["roles"]
	if !search(roles, "mv-admin") {
		return false, errors.New("token not valid")
	}
	return true, nil
}

func search(ss any, s string) bool {
	if s == "" {
		return false
	}
	switch vs := ss.(type) {
	case string:
		if vs == s {
			return true
		}
	case []any:
		for _, l := range vs {
			switch v := l.(type) {
			case string:
				if v == s {
					return true
				}
			}
		}
	}
	return false
}

func hash(p []byte) string {
	var h []byte
	hsh := sha256.Sum256(p)
	h = hsh[:]
	return base64.StdEncoding.EncodeToString(h)
}
