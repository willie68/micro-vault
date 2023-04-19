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
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/serror"
	"github.com/willie68/micro-vault/internal/services/clients"
	"github.com/willie68/micro-vault/internal/services/groups"
	"github.com/willie68/micro-vault/internal/services/keyman"
	"github.com/willie68/micro-vault/internal/services/playbook"
	"github.com/willie68/micro-vault/internal/utils"
	cry "github.com/willie68/micro-vault/pkg/crypt"
	"github.com/willie68/micro-vault/pkg/pmodel"
)

// DoAdmin injection name
const (
	DoAdmin        = "admin"
	tkRolesKey     = "roles"
	tkRoleAdmin    = "mv-admin"
	rtUsageKey     = "usage"
	rtUsageRefresh = "mv-refresh"
	JKAudience     = "microvault-admins"
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
		return "", "", serror.ErrLoginFailed
	}

	no := time.Now()

	// Signing a token (using raw rsa.PrivateKey)
	rtsig, err := a.generateRefreshToken(no)
	if err != nil {
		log.Printf("failed to generate token: %s", err)
		return "", "", err
	}

	tsig, err := a.generateToken(no)
	if err != nil {
		log.Printf("failed to generate token: %s", err)
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
	t.Set(jwt.AudienceKey, JKAudience)
	t.Set(jwt.IssuedAtKey, no)
	t.Set(jwt.ExpirationKey, no.Add(5*time.Minute))
	t.Set(jwt.JwtIDKey, id)
	t.Set(tkRolesKey, []string{tkRoleAdmin})

	// Signing a token (using raw rsa.PrivateKey)
	tsig, err := jwt.Sign(t, jwt.WithKey(jwa.RS256, a.kmn.SignPrivateKey()))
	if err != nil {
		log.Printf("failed to sign token: %s", err)
		return "", err
	}
	return string(tsig), nil
}

func (a *Admin) generateRefreshToken(no time.Time) (string, error) {
	id := utils.GenerateID()
	t := jwt.New()
	t.Set(jwt.AudienceKey, JKAudience)
	t.Set(jwt.IssuedAtKey, no)
	t.Set(jwt.ExpirationKey, no.Add(60*time.Minute))
	t.Set(jwt.JwtIDKey, id)
	t.Set(rtUsageKey, rtUsageRefresh)

	// Signing a token (using raw rsa.PrivateKey)
	tsig, err := jwt.Sign(t, jwt.WithKey(jwa.RS256, a.kmn.SignPrivateKey()))
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
		return model.Group{}, serror.ErrNotExists
	}
	return *g, nil
}

// AddGroup adding a new group to the service
func (a *Admin) AddGroup(tk string, g model.Group) (string, error) {
	err := a.checkTk(tk)
	if err != nil {
		return "", err
	}
	kid, pem, err := generateRSAKey()
	if err != nil {
		return "", err
	}
	g.KID = kid
	g.Key = pem
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
		nc := model.Client{
			Name:      c.Name,
			AccessKey: c.AccessKey,
			Secret:    "",
			Groups:    c.Groups,
		}
		cl = append(cl, nc)
		return true
	})
	return cl, err
}

// Client4Group get defined clients for group
func (a *Admin) Client4Group(tk, g string) ([]model.Client, error) {
	err := a.checkTk(tk)
	if err != nil {
		return []model.Client{}, err
	}
	cl := make([]model.Client, 0)
	g = strings.Trim(g, "\"")
	err = a.stg.ListClients(func(c model.Client) bool {
		if search(c.Groups, g) || g == c.Name {
			nc := model.Client{
				Name:      c.Name,
				AccessKey: c.AccessKey,
				Secret:    "",
				Groups:    c.Groups,
			}
			cl = append(cl, nc)
		}
		return true
	})
	return cl, err
}

// NewClient creating a new client for the system
func (a *Admin) NewClient(tk, n string, gs []string) (*pmodel.Client, error) {
	err := a.checkTk(tk)
	if err != nil {
		return nil, err
	}
	cl, err := a.createClient(n, gs)
	if err != nil {
		return nil, err
	}
	return cl, nil
}

// AddGroups2Client creating a new client for the system
func (a *Admin) AddGroups2Client(tk, n string, gs []string) (*pmodel.Client, error) {
	err := a.checkTk(tk)
	if err != nil {
		return nil, err
	}
	if !a.stg.HasClient(n) {
		return nil, serror.ErrNotExists
	}
	ak, ok := a.stg.AccessKey(n)
	if !ok {
		return nil, serror.ErrNotExists
	}
	c, ok := a.stg.GetClient(ak)
	if !ok {
		return nil, serror.ErrNotExists
	}
	c.Groups = gs
	err = a.stg.UpdateClient(*c)
	if err != nil {
		return nil, err
	}
	co := pmodel.Client{
		Name:      c.Name,
		AccessKey: c.AccessKey,
		Secret:    "*****",
		Groups:    c.Groups,
		KID:       c.KID,
		Key:       c.Key,
	}
	return &co, nil
}

// Client getting a single client based on the name
func (a *Admin) Client(tk, n string) (*model.Client, error) {
	err := a.checkTk(tk)
	if err != nil {
		return nil, err
	}
	if !a.stg.HasClient(n) {
		return nil, serror.ErrNotExists
	}
	ak, ok := a.stg.AccessKey(n)
	if !ok {
		return nil, serror.ErrNotExists
	}
	cl, ok := a.stg.GetClient(ak)
	if !ok {
		return nil, serror.ErrNotExists
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
		return false, serror.ErrNotExists
	}
	ak, ok := a.stg.AccessKey(n)
	if !ok {
		return false, serror.ErrNotExists
	}
	ok, err = a.stg.DeleteClient(ak)
	if err != nil {
		return false, err
	}
	ok, err = a.stg.DeleteGroup(n)
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

// Keys4Group get all defined clients
func (a *Admin) Keys4Group(tk, g string, s, l int64) ([]model.EncryptKey, error) {
	err := a.checkTk(tk)
	if err != nil {
		return []model.EncryptKey{}, err
	}
	cl := make([]model.EncryptKey, 0)
	g = strings.Trim(g, "\"")
	err = a.stg.ListEncryptKeys(s, l, func(c model.EncryptKey) bool {
		if c.Group == g {
			cl = append(cl, c)
		}
		return true
	})
	return cl, err
}

// CreateGroupKey creates a new group key from the administrator endpoint
func (a *Admin) CreateGroupKey(tk, g string) (*model.EncryptKey, error) {
	err := a.checkTk(tk)
	if err != nil {
		return nil, err
	}

	ek, err := a.cls.CreateKey(g)
	if err != nil {
		return nil, err
	}
	return ek, nil
}

func (a *Admin) checkTk(tk string) error {
	token, err := jwt.Parse([]byte(tk), jwt.WithKey(jwa.RS256, a.kmn.PublicKey()))
	if err != nil {
		return err
	}
	et := token.Expiration()
	no := time.Now()
	if no.After(et) {
		return serror.ErrTokenExpired
	}
	roles := token.PrivateClaims()[tkRolesKey]
	if !search(roles, tkRoleAdmin) {
		return serror.ErrTokenNotValid
	}
	return nil
}

// checkRtk checking if the token is a valid refresh token
func (a *Admin) checkRtk(tk string) (jwt.Token, error) {
	token, err := jwt.Parse([]byte(tk), jwt.WithKey(jwa.RS256, a.kmn.PublicKey()))
	if err != nil {
		return nil, err
	}
	auds := token.Audience()
	if len(auds) != 1 {
		return nil, serror.ErrTokenNotValid
	}
	if auds[0] != JKAudience {
		return nil, serror.ErrTokenNotValid
	}
	et := token.Expiration()
	if time.Now().After(et) {
		return nil, serror.ErrTokenExpired
	}
	id := token.JwtID()
	if a.stg.IsRevoked(id) {
		return nil, serror.ErrTokenNotValid
	}
	usage := token.PrivateClaims()[rtUsageKey]
	if usage != rtUsageRefresh {
		return nil, serror.ErrTokenNotValid
	}
	return token, nil
}

// CreateClient creates a new client with defined groups
func (a *Admin) createClient(n string, g []string) (*pmodel.Client, error) {
	if a.stg.HasClient(n) || a.stg.HasGroup(n) {
		return nil, serror.ErrAlreadyExists
	}
	secret, err := generateToken()
	if err != nil {
		return nil, err
	}
	salt, err := cry.GenerateSalt()
	if err != nil {
		return nil, err
	}
	kid, pem, err := generateRSAKey()
	if err != nil {
		return nil, err
	}
	hash := cry.HashSecret(secret, salt)
	c := model.Client{
		Name:      n,
		Salt:      hex.EncodeToString(salt),
		AccessKey: uuid.NewString(),
		Hash:      hash,
		Groups:    g,
		Key:       pem,
		KID:       kid,
	}
	_, err = a.stg.AddClient(c)
	if err != nil {
		return nil, err
	}

	cg := model.Group{
		Name:     c.Name,
		IsClient: true,
	}
	_, err = a.stg.AddGroup(cg)
	if err != nil {
		ak, ok := a.stg.AccessKey(c.Name)
		if ok {
			_, err = a.stg.DeleteClient(ak)
			if err != nil {
				logging.Logger.Errorf("error deleting client after failure of adding client group: %v", err)
			}
		}
		return nil, err
	}
	co := pmodel.Client{
		Name:      c.Name,
		AccessKey: c.AccessKey,
		Secret:    hex.EncodeToString(secret),
		Groups:    c.Groups,
		KID:       c.KID,
		Key:       c.Key,
	}
	return &co, nil
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
	case []string:
		for _, v := range vs {
			if v == s {
				return true
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

func generateRSAKey() (string, string, error) {
	rsk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	pem, err := cry.Prv2Pem(rsk)
	if err != nil {
		return "", "", err
	}
	kid, err := cry.GetKID(rsk)
	if err != nil {
		return "", "", err
	}
	return kid, string(pem), nil
}

func generateToken() ([]byte, error) {
	token := make([]byte, 16)
	_, err := rand.Read(token)
	if err != nil {
		return token, err
	}
	return token, nil
}
