package clients

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/services"
)

// Clients business logic for client management
type Clients struct {
	stg interfaces.Storage
}

// NewClients creates a new clients service
func NewClients(stg interfaces.Storage) (Clients, error) {
	return Clients{
		stg: stg,
	}, nil
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
	t.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/v2/jwt`)
	t.Set(jwt.AudienceKey, `Golang Users`)
	t.Set(jwt.IssuedAtKey, time.Now())
	t.Set(`privateClaimKey`, `Hello, World!`)

	buf, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		fmt.Printf("failed to generate JSON: %s\n", err)
		return "", err
	}

	fmt.Printf("%s\n", buf)
	fmt.Printf("aud -> '%s'\n", t.Audience())
	fmt.Printf("iat -> '%s'\n", t.IssuedAt().Format(time.RFC3339))
	if v, ok := t.Get(`privateClaimKey`); ok {
		fmt.Printf("privateClaimKey -> '%s'\n", v)
	}
	fmt.Printf("sub -> '%s'\n", t.Subject())

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return "", err
	}

	// Signing a token (using raw rsa.PrivateKey)
	signed, err := jwt.Sign(t, jwa.RS256, key)
	if err != nil {
		log.Printf("failed to sign token: %s", err)
		return "", err
	}
	_ = signed

	return string(signed), nil

}
