package admin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services"
	"github.com/willie68/micro-vault/internal/services/clients"
	"github.com/willie68/micro-vault/internal/services/groups"
	"github.com/willie68/micro-vault/internal/services/keyman"
	"github.com/willie68/micro-vault/internal/services/playbook"
	"github.com/willie68/micro-vault/internal/utils"
	cry "github.com/willie68/micro-vault/pkg/crypt"
)

// DoAdmin injection name
const (
	DoAdmin     = "admin"
	tkRolesKey  = "roles"
	tkRoleAdmin = "mv-admin"
	rtUsageKey  = "usage"
	rtUsage     = "mv-refresh"
)

// Admin admin service business logic
type Admin struct {
	rootusr string
	pwdhash string
	stg     interfaces.Storage
	kmn     keyman.Keyman
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
		kmn:     do.MustInvokeNamed[keyman.Keyman](nil, keyman.DoKeyman),
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

// LoginUP logging in an admin account
func (a *Admin) LoginUP(u string, p []byte) (string, string, error) {
	if !strings.EqualFold(u, a.rootusr) || hash(p) != a.pwdhash {
		return "", "", services.ErrLoginFailed
	}

	no := time.Now()

	// Signing a token (using raw rsa.PrivateKey)
	rtsig, err := a.generateRefreshToken(no)
	if err != nil {
		log.Printf("failed to sign token: %s", err)
		return "", "", err
	}

	tsig, err := a.generateToken(no)
	if err != nil {
		log.Printf("failed to sign token: %s", err)
		return "", "", err
	}

	return tsig, rtsig, nil
}

// Refresh refreshing an admin account
func (a *Admin) Refresh(rt string) (string, string, error) {
	tk, err := a.checkRtk(rt)
	if err != nil {
		return "", "", err
	}

	no := time.Now()
	// Signing a token (using raw rsa.PrivateKey)
	rtsig, err := a.generateRefreshToken(no)
	if err != nil {
		log.Printf("failed to sign token: %s", err)
		return "", "", err
	}

	tsig, err := a.generateToken(no)
	if err != nil {
		log.Printf("failed to sign token: %s", err)
		return "", "", err
	}

	// refresh token is used, so it can be revoked
	exp := tk.Expiration()
	err = a.stg.RevokeToken(tk.JwtID(), exp)
	if err != nil {
		log.Printf("failed to revoke token: %s", err)
	}

	return tsig, rtsig, nil
}

func (a *Admin) generateToken(no time.Time) (string, error) {
	id := utils.GenerateID()
	t := jwt.New()
	t.Set(jwt.AudienceKey, "microvault-admins")
	t.Set(jwt.IssuedAtKey, no)
	t.Set(jwt.ExpirationKey, no.Add(5*time.Minute))
	t.Set(jwt.JwtIDKey, id)
	t.Set(tkRolesKey, []string{tkRoleAdmin})

	// Signing a token (using raw rsa.PrivateKey)
	tsig, err := jwt.Sign(t, jwa.RS256, a.kmn.PrivateKey())
	if err != nil {
		log.Printf("failed to sign token: %s", err)
		return "", err
	}
	return string(tsig), nil
}

func (a *Admin) generateRefreshToken(no time.Time) (string, error) {
	id := utils.GenerateID()
	t := jwt.New()
	t.Set(jwt.AudienceKey, "microvault-admins")
	t.Set(jwt.IssuedAtKey, no)
	t.Set(jwt.ExpirationKey, no.Add(60*time.Minute))
	t.Set(jwt.JwtIDKey, id)
	t.Set(rtUsageKey, rtUsage)

	// Signing a token (using raw rsa.PrivateKey)
	tsig, err := jwt.Sign(t, jwa.RS256, a.kmn.PrivateKey())
	if err != nil {
		log.Printf("failed to sign token: %s", err)
		return "", err
	}
	return string(tsig), nil
}

// Playbook plays the playbook
func (a *Admin) Playbook(tk string, pm model.Playbook) error {
	err := a.checkTk(tk)
	if err != nil {
		return err
	}
	pb := playbook.NewPlaybook(pm)
	return pb.Play()
}

// Groups getting all defined groups
func (a *Admin) Groups(tk string) ([]model.Group, error) {
	err := a.checkTk(tk)
	if err != nil {
		return []model.Group{}, err
	}
	return a.stg.GetGroups()
}

// HasGroup checking existence of group
func (a *Admin) HasGroup(tk string, n string) bool {
	err := a.checkTk(tk)
	if err != nil {
		return false
	}
	return a.stg.HasGroup(n)
}

// Group getting a group
func (a *Admin) Group(tk string, n string) (model.Group, error) {
	err := a.checkTk(tk)
	if err != nil {
		return model.Group{}, err
	}
	g, ok := a.stg.GetGroup(n)
	if !ok {
		return model.Group{}, services.ErrNotExists
	}
	return *g, nil
}

// AddGroup adding a new group to the service
func (a *Admin) AddGroup(tk string, g model.Group) (string, error) {
	err := a.checkTk(tk)
	if err != nil {
		return "", err
	}
	return a.grs.AddGroup(g)
}

// DeleteGroup adding a new group to the service
func (a *Admin) DeleteGroup(tk string, n string) (bool, error) {
	err := a.checkTk(tk)
	if err != nil {
		return false, err
	}
	return a.grs.DeleteGroup(n), nil
}

// Clients get all defined clients
func (a *Admin) Clients(tk string) ([]model.Client, error) {
	err := a.checkTk(tk)
	if err != nil {
		return []model.Client{}, err
	}
	cl := make([]model.Client, 0)
	err = a.stg.ListClients(func(c model.Client) bool {
		cl = append(cl, c)
		return true
	})
	return cl, err
}

// NewClient creating a new client for the system
func (a *Admin) NewClient(tk, n string, gs []string) (*model.Client, error) {
	err := a.checkTk(tk)
	if err != nil {
		return nil, err
	}
	if a.stg.HasClient(n) {
		return nil, services.ErrAlreadyExists
	}
	cl, err := a.createClient(n, gs)
	if err != nil {
		return nil, err
	}
	return cl, nil
}

// Client getting a single client based on the name
func (a *Admin) Client(tk, n string) (*model.Client, error) {
	err := a.checkTk(tk)
	if err != nil {
		return nil, err
	}
	if !a.stg.HasClient(n) {
		return nil, services.ErrNotExists
	}
	ak, ok := a.stg.AccessKey(n)
	if !ok {
		return nil, services.ErrNotExists
	}
	cl, ok := a.stg.GetClient(ak)
	if !ok {
		return nil, services.ErrNotExists
	}
	c := model.Client{
		Name:      cl.Name,
		AccessKey: cl.AccessKey,
		Secret:    "",
		Groups:    cl.Groups,
	}
	return &c, nil
}

// DeleteClient deleting a client
func (a *Admin) DeleteClient(tk, n string) (bool, error) {
	err := a.checkTk(tk)
	if err != nil {
		return false, err
	}
	if !a.stg.HasClient(n) {
		return false, services.ErrNotExists
	}
	ak, ok := a.stg.AccessKey(n)
	if !ok {
		return false, services.ErrNotExists
	}
	ok, err = a.stg.DeleteClient(ak)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// Keys get all defined clients
func (a *Admin) Keys(tk string, s, l int64) ([]model.EncryptKey, error) {
	err := a.checkTk(tk)
	if err != nil {
		return []model.EncryptKey{}, err
	}
	cl := make([]model.EncryptKey, 0)
	err = a.stg.ListEncryptKeys(s, l, func(c model.EncryptKey) bool {
		cl = append(cl, c)
		return true
	})
	return cl, err
}

func (a *Admin) checkTk(tk string) error {
	token, err := jwt.Parse([]byte(tk), jwt.WithVerify(jwa.RS256, a.kmn.PublicKey()))
	if err != nil {
		return err
	}
	et := token.Expiration()
	no := time.Now()
	if no.After(et) {
		return services.ErrTokenExpired
	}
	roles := token.PrivateClaims()[tkRolesKey]
	if !search(roles, tkRoleAdmin) {
		return services.ErrTokenNotValid
	}
	return nil
}

func (a *Admin) checkRtk(tk string) (jwt.Token, error) {
	token, err := jwt.Parse([]byte(tk), jwt.WithVerify(jwa.RS256, a.kmn.PublicKey()))
	if err != nil {
		return nil, err
	}
	et := token.Expiration()
	if time.Now().After(et) {
		return nil, services.ErrTokenExpired
	}
	id := token.JwtID()
	if a.stg.IsRevoked(id) {
		return nil, services.ErrTokenNotValid
	}
	usage := token.PrivateClaims()[rtUsageKey]
	if usage != rtUsage {
		return nil, services.ErrTokenNotValid
	}
	return token, nil
}

// CreateClient creates a new client with defined groups
func (a *Admin) createClient(n string, g []string) (*model.Client, error) {
	token := make([]byte, 16)
	_, err := rand.Read(token)
	if err != nil {
		return nil, err
	}
	rsk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pem, err := cry.Prv2Pem(rsk)
	if err != nil {
		return nil, err
	}
	kid, err := cry.GetKID(rsk)
	if err != nil {
		return nil, err
	}
	c := model.Client{
		Name:      n,
		AccessKey: uuid.NewString(),
		Secret:    hex.EncodeToString(token),
		Groups:    g,
		Key:       string(pem),
		KID:       kid,
	}
	_, err = a.stg.AddClient(c)
	if err != nil {
		return nil, err
	}
	return &c, nil
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
