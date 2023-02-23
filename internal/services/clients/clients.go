package clients

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/rs/xid"
	"github.com/willie68/micro-vault/internal/auth"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services"
)

// Clients business logic for client management
type Clients struct {
	stg    interfaces.Storage
	srvkey jwk.Key
	kid    string
}

// NewClients creates a new clients service
func NewClients(stg interfaces.Storage) (Clients, error) {
	c := Clients{
		stg: stg,
	}
	err := c.Init()
	return c, err
}

// KID getting the kid
func (c *Clients) KID() string {
	return c.kid
}

// Init initialize the clients service
func (c *Clients) Init() error {
	rsk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return err
	}
	key, err := jwk.New(rsk)
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
	jt, err := auth.DecodeJWT(tk)
	if err != nil {
		return nil, err
	}
	if !jt.IsValid {
		return nil, errors.New("token not valid")
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
	jt, err := auth.DecodeJWT(tk)
	if err != nil {
		return nil, err
	}
	if !jt.IsValid {
		return nil, errors.New("token not valid")
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
