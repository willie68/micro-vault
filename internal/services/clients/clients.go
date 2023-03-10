package clients

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/rs/xid"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/auth"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services"
	"github.com/willie68/micro-vault/internal/services/keyman"
	cry "github.com/willie68/micro-vault/pkg/crypt"
	"github.com/willie68/micro-vault/pkg/pmodel"
)

// DoClients constant for dependency injection
const DoClients = "clients"

// Clients business logic for client management
type Clients struct {
	stg     interfaces.Storage
	srvkey  jwk.Key
	kid     string
	pubkeys sync.Map
	cfg     config.Config
	kmn     keyman.Keyman
}

// NewClients creates a new clients service
func NewClients() (Clients, error) {
	c := Clients{
		stg: do.MustInvokeNamed[interfaces.Storage](nil, interfaces.DoStorage),
		cfg: do.MustInvokeNamed[config.Config](nil, config.DoServiceConfig),
		kmn: do.MustInvokeNamed[keyman.Keyman](nil, keyman.DoKeyman),
	}
	err := c.Init()
	if err != nil {
		return Clients{}, err
	}
	do.ProvideNamedValue[Clients](nil, DoClients, c)
	return c, err
}

// KID getting the kid
func (c *Clients) KID() string {
	return c.kid
}

// Key getting the server key
func (c *Clients) Key() jwk.Key {
	return c.srvkey
}

// Init initialize the clients service
func (c *Clients) Init() error {
	var err error

	key, err := jwk.New(c.kmn.PrivateKey())

	err = jwk.AssignKeyID(key)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return err
	}
	c.srvkey = key
	c.kid = key.KeyID()
	return nil
}

// Login logging in a client, returning a token if ok
func (c *Clients) Login(a, s string) (string, error) {
	if !c.stg.HasClient(a) {
		return "", services.ErrLoginFailed
	}
	cl, ok := c.stg.GetClient(a)
	if ok && cl.Secret != s {
		return "", services.ErrLoginFailed
	}

	t := jwt.New()
	t.Set(jwt.AudienceKey, "microvault-clients")
	t.Set(jwt.IssuedAtKey, time.Now())
	t.Set(jwt.ExpirationKey, time.Now().Add(5*time.Minute))
	t.Set("name", cl.Name)
	t.Set("groups", cl.Groups)

	// Signing a token (using raw rsa.PrivateKey)
	signed, err := jwt.Sign(t, jwa.RS256, c.srvkey)
	if err != nil {
		log.Printf("failed to sign token: %s", err)
		return "", err
	}
	return string(signed), nil
}

// CreateEncryptKey creates a new encryption key, stores it into the storage with id
func (c *Clients) CreateEncryptKey(tk string, group string) (*model.EncryptKey, error) {
	jt, err := c.checkTk(tk)
	if err != nil {
		return nil, err
	}
	gr, ok := jt.Payload["groups"]
	if !ok {
		return nil, errors.New("token not valid, no groups")
	}
	f := search(gr, group)
	if !f {
		return nil, errors.New("group not valid, can't create a key for this group")
	}
	id := xid.New().String()
	buf := make([]byte, 32)
	_, err = rand.Read(buf)
	if err != nil {
		return nil, err
	}
	_, err = aes.NewCipher(buf)
	if err != nil {
		return nil, err
	}

	e := model.EncryptKey{
		ID:      id,
		Alg:     "AES-256",
		Key:     hex.EncodeToString(buf),
		Created: time.Now(),
		Group:   group,
	}
	err = c.stg.StoreEncryptKey(e)
	return &e, nil
}

// GetEncryptKey get an encryption key with id
func (c *Clients) GetEncryptKey(tk string, id string) (*model.EncryptKey, error) {
	jt, err := c.checkTk(tk)
	if err != nil {
		return nil, err
	}
	gr, ok := jt.Payload["groups"]
	if !ok {
		return nil, errors.New("token not valid, no groups")
	}

	e, ok := c.stg.GetEncryptKey(id)
	if !ok {
		return nil, services.ErrNotExists
	}

	f := search(gr, e.Group)
	if !f {
		return nil, errors.New("access to key permitted")
	}

	return e, nil
}

// SetCertificate set the public certificate for this client
func (c *Clients) SetCertificate(tk string, pc string) error {
	jt, err := c.checkTk(tk)
	if err != nil {
		return err
	}
	name, ok := jt.Payload["name"]
	if !ok {
		return services.ErrNotExists
	}
	c.pubkeys.Store(name, pc)
	return nil
}

// GetCertificate get the public certificate for another client (by name)
func (c *Clients) GetCertificate(tk string, cl string) (string, error) {
	if _, err := c.checkTk(tk); err != nil {
		return "", err
	}
	var dc *model.Client
	c.stg.ListClients(func(g model.Client) bool {
		if g.Name == cl {
			dc = &g
			return false
		}
		return true
	})
	if dc == nil {
		return "", services.ErrUnknowError
	}
	b, ok := c.pubkeys.Load(dc.Name)
	if !ok {
		return "", services.ErrUnknowError
	}
	bs, ok := b.(string)
	if !ok {
		return "", services.ErrUnknowError
	}
	return bs, nil
}

// CryptSS server side en/decryption method
func (c *Clients) CryptSS(tk string, msg pmodel.Message) (*pmodel.Message, error) {
	_, err := c.checkTk(tk)
	if err != nil {
		return nil, err
	}

	if strings.EqualFold(msg.Type, "group") {
		return c.ssGroup(tk, msg)
	}
	if strings.EqualFold(msg.Type, "private") {
		return c.ssClient(tk, msg)
	}
	return &msg, nil
}

func (c *Clients) ssGroup(tk string, msg pmodel.Message) (*pmodel.Message, error) {
	if msg.Decrypt {
		if msg.ID == "" {
			return nil, errors.New("missing key id")
		}
		key, err := c.GetEncryptKey(tk, msg.ID)
		if err != nil {
			return nil, err
		}
		k, err := hex.DecodeString(key.Key)
		if err != nil {
			return nil, err
		}
		m, err := cry.Decrypt(k, msg.Message)
		if err != nil {
			return nil, err
		}
		msg.Message = m
		msg.Decrypt = false
		return &msg, nil
	}
	// Encrypt
	var key *model.EncryptKey
	var err error
	if msg.ID == "" {
		key, err = c.CreateEncryptKey(tk, msg.Recipient)
	} else {
		key, err = c.GetEncryptKey(tk, msg.ID)
	}
	if err != nil {
		return nil, err
	}
	k, err := hex.DecodeString(key.Key)
	if err != nil {
		return nil, err
	}
	m, err := cry.Encrypt(k, msg.Message)
	if err != nil {
		return nil, err
	}
	msg.ID = key.ID
	msg.Recipient = key.Group
	msg.Message = m
	msg.Decrypt = true
	return &msg, nil
}

func (c *Clients) ssClient(tk string, msg pmodel.Message) (*pmodel.Message, error) {
	if !msg.Decrypt {
		if msg.Recipient == "" {
			return nil, errors.New("missing recipient")
		}
		key, err := c.GetCertificate(tk, msg.Recipient)
		if err != nil {
			return nil, err
		}

		pub, err := cry.Pem2pub(key)
		if err != nil {
			return nil, err
		}

		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte(msg.Message), nil)

		if err != nil {
			return nil, err
		}
		// convert to base64
		msg.Message = base64.StdEncoding.EncodeToString(ciphertext)
		msg.Decrypt = true
		return &msg, nil
	}
	return nil, errors.New("server side private decryption is not supported")
}

func (c *Clients) checkTk(tk string) (*auth.JWT, error) {
	jt, err := auth.DecodeJWT(tk)
	if err != nil {
		return nil, err
	}
	if !jt.IsValid {
		return nil, errors.New("token not valid")
	}
	return &jt, nil
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
