package clients

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/xid"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/serror"
	"github.com/willie68/micro-vault/internal/services/keyman"
	"github.com/willie68/micro-vault/internal/utils"
	cry "github.com/willie68/micro-vault/pkg/crypt"
	"github.com/willie68/micro-vault/pkg/pmodel"
	"golang.org/x/exp/slices"
)

// DoClients constant for dependency injection
const (
	DoClients      = "clients"
	JKAudience     = "microvault-client"
	rtUsageKey     = "usage"
	rtUsageRefresh = "mv-refresh"
)

// Clients business logic for client management
type Clients struct {
	stg  interfaces.Storage
	cfg  config.Config
	kmn  keyman.Keyman
	crt  keyman.CAService
	kids map[string]string // map key is the kid, value is the access key of the client
}

// NewClients creates a new clients service
func NewClients() (Clients, error) {
	c := Clients{
		stg: do.MustInvokeNamed[interfaces.Storage](nil, interfaces.DoStorage),
		cfg: do.MustInvokeNamed[config.Config](nil, config.DoServiceConfig),
		kmn: do.MustInvokeNamed[keyman.Keyman](nil, keyman.DoKeyman),
		crt: do.MustInvokeNamed[keyman.CAService](nil, keyman.DoCAService),
	}
	err := c.Init()
	if err != nil {
		return Clients{}, err
	}
	do.ProvideNamedValue[Clients](nil, DoClients, c)
	return c, err
}

// Init initialize the clients service
func (c *Clients) Init() error {
	c.kids = make(map[string]string)
	c.stg.ListClients(func(g model.Client) bool {
		if g.KID == "" {
			kid, err := cry.GetKIDOfPEM(g.Key)
			if err != nil {
				return true
			}
			g.KID = kid
		}
		c.kids[g.KID] = g.AccessKey
		return true
	})
	return nil
}

// Login logging in a client, returning a token if ok,
// return token, refreshtoken, key, error
func (c *Clients) Login(a, s string) (string, string, string, error) {
	if !c.stg.HasClient(a) {
		return "", "", "", serror.ErrLoginFailed
	}
	cl, ok := c.stg.GetClient(a)
	salt, err := hex.DecodeString(cl.Salt)
	if err != nil {
		log.Printf("failed to generate salt: %s", err)
		return "", "", "", err
	}
	secret, err := hex.DecodeString(s)
	if err != nil {
		log.Printf("failed to decode secret: %s", err)
		return "", "", "", err
	}
	hash := cry.HashSecret(secret, salt)
	if !ok || (ok && cl.Hash != hash) {
		return "", "", "", serror.ErrLoginFailed
	}

	no := time.Now()

	// Signing a token (using raw rsa.PrivateKey)
	rtsig, err := c.generateRefreshToken(no, cl.Name)
	if err != nil {
		log.Printf("failed to generate token: %s", err)
		return "", "", "", err
	}

	tsig, err := c.generateToken(no, cl.Name, cl.Groups)
	if err != nil {
		log.Printf("failed to generate token: %s", err)
		return "", "", "", err
	}

	return tsig, rtsig, cl.Key, nil
}

// Refresh refreshing an admin account
func (c *Clients) Refresh(rt string) (string, string, error) {
	tk, err := c.checkRtk(rt)
	if err != nil {
		return "", "", err
	}

	n, ok := tk.PrivateClaims()["name"].(string)
	if !ok {
		logging.Logger.Error("failed to refresh, token not valid")
		return "", "", serror.ErrTokenNotValid
	}

	a, ok := c.stg.AccessKey(n)
	if !ok {
		logging.Logger.Error("failed to refresh, token not valid")
		return "", "", serror.ErrTokenNotValid
	}
	cl, ok := c.stg.GetClient(a)
	if !ok {
		logging.Logger.Error("failed to refresh, token not valid")
		return "", "", serror.ErrTokenNotValid
	}

	no := time.Now()
	// Signing a token (using raw rsa.PrivateKey)
	rtsig, err := c.generateRefreshToken(no, cl.Name)
	if err != nil {
		logging.Logger.Errorf("failed to sign token: %s", err)
		return "", "", err
	}

	tsig, err := c.generateToken(no, cl.Name, cl.Groups)
	if err != nil {
		logging.Logger.Errorf("failed to sign token: %s", err)
		return "", "", err
	}

	// refresh token is used, so it can be revoked
	exp := tk.Expiration()
	err = c.stg.RevokeToken(tk.JwtID(), exp)
	if err != nil {
		logging.Logger.Errorf("failed to revoke token: %s", err)
	}

	return tsig, rtsig, nil
}

func (c *Clients) generateToken(no time.Time, n string, gr []string) (string, error) {
	id := utils.GenerateID()
	t := jwt.New()
	t.Set(jwt.AudienceKey, JKAudience)
	t.Set(jwt.IssuedAtKey, no)
	t.Set(jwt.ExpirationKey, no.Add(5*time.Minute))
	t.Set(jwt.JwtIDKey, id)
	t.Set("name", n)
	t.Set("groups", gr)

	// Signing a token (using raw rsa.PrivateKey)
	tsig, err := jwt.Sign(t, jwt.WithKey(jwa.RS256, c.kmn.SignPrivateKey()))
	if err != nil {
		log.Printf("failed to sign token: %s", err)
		return "", err
	}
	return string(tsig), nil
}

func (c *Clients) generateRefreshToken(no time.Time, n string) (string, error) {
	id := utils.GenerateID()
	t := jwt.New()
	t.Set(jwt.AudienceKey, JKAudience)
	t.Set(jwt.IssuedAtKey, no)
	t.Set(jwt.ExpirationKey, no.Add(60*time.Minute))
	t.Set(jwt.JwtIDKey, id)
	t.Set("name", n)
	t.Set(rtUsageKey, rtUsageRefresh)

	tsig, err := jwt.Sign(t, jwt.WithKey(jwa.RS256, c.kmn.SignPrivateKey()))
	if err != nil {
		logging.Logger.Errorf("failed to sign token: %s", err)
		return "", err
	}
	return string(tsig), nil
}

// CreateCertificate generate a new certificate for the client, signed with the CA cert
func (c *Clients) CreateCertificate(tk string, certTemplate string) (string, error) {
	_, err := c.checkTk(tk)
	if err != nil {
		return "", err
	}
	cl, err := c.client(tk)
	if err != nil {
		return "", err
	}
	pk, err := cry.Pem2Prv(cl.Key)
	if err != nil {
		return "", err
	}

	p, _ := pem.Decode([]byte(certTemplate))
	if p == nil {
		return "", errors.New("no pem block found")
	}
	if p.Type != "CERTIFICATE REQUEST" {
		return "", errors.New("wrong pem block found, must be \"CERTIFICATE REQUEST\"")
	}
	tmp, err := x509.ParseCertificateRequest(p.Bytes)
	if err != nil {
		return "", err
	}
	tmp, err = c.mergeTemplate(tmp, cl.Crt)
	if err != nil {
		return "", err
	}

	b, err := c.crt.CertSignRequest(*tmp, &pk.PublicKey)
	if err != nil {
		return "", err
	}

	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	})
	if err != nil {
		return "", err
	}
	return caPEM.String(), nil
}

// GetPrivateKey get the private certificate for the client
func (c *Clients) GetPrivateKey(tk string) (string, error) {
	_, err := c.checkTk(tk)
	if err != nil {
		return "", err
	}
	cl, err := c.client(tk)
	if err != nil {
		return "", err
	}
	return string(cl.Key), nil
}

// CreateEncryptKey creates a new encryption key, stores it into the storage with id
func (c *Clients) CreateEncryptKey(tk string, group string) (*model.EncryptKey, error) {
	jt, err := c.checkTk(tk)
	if err != nil {
		return nil, err
	}
	gr, ok := jt.PrivateClaims()["groups"]
	if !ok {
		return nil, errors.New("token not valid, no groups")
	}
	n, ok := jt.PrivateClaims()["name"].(string)
	f := search(gr, group)
	if !f && (!ok || (group != n)) {
		return nil, errors.New("group not valid, can't create a key for this group")
	}
	return c.CreateKey(group)
}

// CreateKey creates a new encryption key for a specifig group
func (c *Clients) CreateKey(group string) (*model.EncryptKey, error) {
	id := xid.New().String()
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
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
	gr, ok := jt.PrivateClaims()["groups"]
	if !ok {
		return nil, errors.New("token not valid, no groups")
	}

	e, ok := c.stg.GetEncryptKey(id)
	if !ok {
		return nil, serror.ErrNotExists
	}

	n, ok := jt.PrivateClaims()["name"].(string)
	f := search(gr, e.Group)
	if !f && (!ok || (e.Group != n)) {
		return nil, errors.New("access to key permitted")
	}

	return e, nil
}

// GetPublicKey get the public key of another client (by name)
func (c *Clients) GetPublicKey(tk string, cl string) (string, error) {
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
		return "", serror.ErrUnknowError
	}
	k, err := cry.Pem2Prv(dc.Key)
	if err != nil {
		return "", err
	}
	ks, err := cry.Pub2Pem(&k.PublicKey)
	if err != nil {
		return "", err
	}
	return string(ks), nil
}

// SignSS server side signature
func (c *Clients) SignSS(tk string, msg *pmodel.SignMessage) (*pmodel.SignMessage, error) {
	_, err := c.checkTk(tk)
	if err != nil {
		return nil, err
	}
	cl, err := c.client(tk)
	if err != nil {
		return nil, err
	}
	pk, err := cry.Pem2Prv(cl.Key)
	if err != nil {
		return nil, err
	}

	kid, err := cry.GetKID(pk)
	if err != nil {
		logging.Logger.Infof("failed to generate kid: %s", err)
		return nil, err
	}

	sig, err := cry.Sign(*pk, msg.Message)
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	ki := pmodel.KeyInfo{
		Alg: "RS256",
		KID: kid,
	}
	msg.KeyInfo = ki
	return msg, nil
}

// CheckSS server side check signature
func (c *Clients) CheckSS(tk string, msg *pmodel.SignMessage) (*pmodel.SignMessage, error) {
	_, err := c.checkTk(tk)
	if err != nil {
		return nil, err
	}
	var cl *model.Client
	a, ok := c.kids[msg.KeyInfo.KID]
	if !ok {
		cl, ok = c.stg.ClientByKID(msg.KeyInfo.KID)
		if !ok {
			return nil, serror.ErrNotExists
		}
		c.kids[cl.KID] = cl.AccessKey
		a = cl.AccessKey
	} else {
		cl, ok = c.stg.GetClient(a)
	}
	rsk, err := cry.Pem2Prv(cl.Key)
	if err != nil {
		return nil, err
	}

	ok, err = cry.SignCheck(&rsk.PublicKey, msg.Signature, msg.Message)
	if err != nil {
		return nil, err
	}

	msg.Valid = ok
	return msg, nil
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

// StoreData stores data secruly for a client/group, returning the id
func (c *Clients) StoreData(tk string, msg pmodel.Message) (string, error) {
	jt, err := c.checkTk(tk)
	if err != nil {
		return "", err
	}
	// prepare the model for storing...
	msg.ID = xid.New().String()
	msg.Decrypt = false
	n, ok := jt.PrivateClaims()["name"].(string)
	if !ok {
		return "", serror.ErrTokenNotValid
	}
	msg.Origin = n

	js, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	dt := model.Data{
		ID:      msg.ID,
		Created: time.Now(),
		Group:   msg.Recipient,
		Payload: string(js),
	}
	err = c.stg.StoreData(dt)
	if err != nil {
		return "", err
	}
	return dt.ID, nil
}

// GetData retrieving securly stored data, if allowed
func (c *Clients) GetData(tk, id string) (*pmodel.Message, error) {
	jt, err := c.checkTk(tk)
	if err != nil {
		return nil, err
	}

	gr, ok := jt.PrivateClaims()["groups"]
	if !ok {
		return nil, errors.New("token not valid, no groups")
	}

	dt, ok := c.stg.GetData(id)
	if !ok {
		return nil, serror.ErrNotExists
	}

	n, ok := jt.PrivateClaims()["name"].(string)
	f := search(gr, dt.Group)
	if !f && (!ok || (dt.Group != n)) {
		return nil, errors.New("access to key permitted")
	}
	var msg pmodel.Message
	err = json.Unmarshal([]byte(dt.Payload), &msg)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

// DeleteData deleting securly stored data
func (c *Clients) DeleteData(tk, id string) (bool, error) {
	jt, err := c.checkTk(tk)
	if err != nil {
		return false, err
	}

	gr, ok := jt.PrivateClaims()["groups"]
	if !ok {
		return false, errors.New("token not valid, no groups")
	}

	dt, ok := c.stg.GetData(id)
	if !ok {
		return false, nil
	}

	n, ok := jt.PrivateClaims()["name"].(string)
	f := search(gr, dt.Group)
	if !f && (!ok || (dt.Group != n)) {
		return false, errors.New("access to key permitted")
	}

	return c.stg.DeleteData(id)
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
		key, err := c.GetPublicKey(tk, msg.Recipient)
		if err != nil {
			return nil, err
		}

		pub, err := cry.Pem2Pub(key)
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

func (c *Clients) checkTk(tk string) (jwt.Token, error) {
	jt, err := jwt.Parse([]byte(tk), jwt.WithKey(jwa.RS256, c.kmn.PrivateKey()))
	if err != nil {
		return nil, err
	}
	auds := jt.Audience()
	if len(auds) != 1 {
		return nil, serror.ErrTokenNotValid
	}
	if auds[0] != JKAudience {
		return nil, serror.ErrTokenNotValid
	}
	et := jt.Expiration()
	if time.Now().After(et) {
		return nil, serror.ErrTokenExpired
	}
	return jt, nil
}

func (c *Clients) checkRtk(tk string) (jwt.Token, error) {
	jt, err := jwt.Parse([]byte(tk), jwt.WithKey(jwa.RS256, c.kmn.PublicKey()))
	if err != nil {
		return nil, err
	}
	auds := jt.Audience()
	if len(auds) != 1 {
		return nil, serror.ErrTokenNotValid
	}
	if auds[0] != JKAudience {
		return nil, serror.ErrTokenNotValid
	}
	et := jt.Expiration()
	if time.Now().After(et) {
		return nil, serror.ErrTokenExpired
	}
	id := jt.JwtID()
	if c.stg.IsRevoked(id) {
		return nil, serror.ErrTokenNotValid
	}
	usage := jt.PrivateClaims()[rtUsageKey]
	if usage != rtUsageRefresh {
		return nil, serror.ErrTokenNotValid
	}
	return jt, nil
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
			v, ok := l.(string)
			if ok && (v == s) {
				return true
			}
		}
	}
	return false
}

func (c *Clients) client(tk string) (*model.Client, error) {
	jt, err := c.checkTk(tk)
	if err != nil {
		return nil, err
	}

	n, ok := jt.PrivateClaims()["name"]
	if !ok {
		return nil, errors.New("token not valid, no name")
	}
	name, ok := n.(string)
	if !ok {
		return nil, errors.New("wrong format")
	}

	a, ok := c.stg.AccessKey(name)
	if !ok {
		return nil, errors.New("name not valid")
	}

	cl, ok := c.stg.GetClient(a)
	if !ok {
		return nil, errors.New("client unknown")
	}
	return cl, nil
}

func (c *Clients) mergeTemplate(tmp *x509.CertificateRequest, crt map[string]any) (*x509.CertificateRequest, error) {
	if tmp.Subject.CommonName == "" {
		tmp.Subject.CommonName = crt["ucn"].(string)
	}
	if (len(tmp.Subject.Country) == 0) && (crt["uco"] != nil) {
		if tmp.Subject.Country == nil {
			tmp.Subject.Country = make([]string, 0)
		}
		tmp.Subject.Country = append(tmp.Subject.Country, crt["uco"].(string))
	}
	if (len(tmp.Subject.Province) == 0) && (crt["upr"] != nil) {
		if tmp.Subject.Province == nil {
			tmp.Subject.Province = make([]string, 0)
		}
		tmp.Subject.Province = append(tmp.Subject.Province, crt["upr"].(string))
	}
	if (len(tmp.Subject.Locality) == 0) && (crt["ulo"] != nil) {
		if tmp.Subject.Locality == nil {
			tmp.Subject.Locality = make([]string, 0)
		}
		tmp.Subject.Locality = append(tmp.Subject.Locality, crt["ulo"].(string))
	}
	if (len(tmp.Subject.Organization) == 0) && (crt["uor"] != nil) {
		if tmp.Subject.Organization == nil {
			tmp.Subject.Organization = make([]string, 0)
		}
		tmp.Subject.Organization = append(tmp.Subject.Organization, crt["uor"].(string))
	}
	if (len(tmp.Subject.OrganizationalUnit) == 0) && (crt["uou"] != nil) {
		if tmp.Subject.OrganizationalUnit == nil {
			tmp.Subject.OrganizationalUnit = make([]string, 0)
		}
		tmp.Subject.OrganizationalUnit = append(tmp.Subject.OrganizationalUnit, crt["uou"].(string))
	}
	if (len(tmp.Subject.StreetAddress) == 0) && (crt["usa"] != nil) {
		if tmp.Subject.StreetAddress == nil {
			tmp.Subject.StreetAddress = make([]string, 0)
		}
		tmp.Subject.StreetAddress = append(tmp.Subject.StreetAddress, crt["usa"].(string))
	}
	if (len(tmp.Subject.PostalCode) == 0) && (crt["upc"] != nil) {
		if tmp.Subject.PostalCode == nil {
			tmp.Subject.PostalCode = make([]string, 0)
		}
		tmp.Subject.PostalCode = append(tmp.Subject.PostalCode, crt["upc"].(string))
	}

	if crt["uem"] != nil {
		if tmp.EmailAddresses == nil {
			tmp.EmailAddresses = make([]string, 0)
		}
		tmp.EmailAddresses = append(tmp.EmailAddresses, crt["uem"].(string))
	}

	var err error
	tmp.DNSNames, err = c.mergeDNSs(crt, tmp.DNSNames)
	if err != nil {
		return nil, err
	}

	tmp.IPAddresses, err = c.mergeIPs(crt, tmp.IPAddresses)
	if err != nil {
		return nil, err
	}

	tmp.URIs, err = c.mergeURIs(crt, tmp.URIs)
	if err != nil {
		return nil, err
	}
	return tmp, nil
}

func (c *Clients) mergeDNSs(crt map[string]any, tmpDNSs []string) ([]string, error) {
	dnss := make([]string, 0)
	if tmpDNSs != nil {
		dnss = append(dnss, tmpDNSs...)
	}
	if crt["dns"] != nil {
		switch v := crt["dns"].(type) {
		case string:
			dnss = append(dnss, v)
		case []string:
			dnss = append(dnss, v...)
		case []any:
			for _, mv := range v {
				dns, ok := mv.(string)
				if ok {
					dnss = append(dnss, dns)
				}
			}
		}
		slices.Sort(dnss)
		dnss = slices.Compact(dnss)
	}
	return dnss, nil
}

func (c *Clients) mergeIPs(crt map[string]any, tmpIPs []net.IP) ([]net.IP, error) {
	ips := make([]net.IP, 0)
	if tmpIPs != nil {
		ips = append(ips, tmpIPs...)
	}
	if crt["ip"] != nil {
		ipsv, err := buildIPList(crt["ip"])
		if err != nil {
			return nil, err
		}
		ips = append(ips, ipsv...)
		slices.SortFunc(ips, func(a, b net.IP) int {
			return strings.Compare(a.String(), b.String())
		})
		return slices.CompactFunc(ips, func(e1, e2 net.IP) bool {
			return e1.Equal(e2)
		}), nil
	}
	return ips, nil
}

func buildIPList(crtIPs any) ([]net.IP, error) {
	ips := make([]net.IP, 0)
	switch v := crtIPs.(type) {
	case string:
		ip := net.ParseIP(v)
		ips = append(ips, ip)
	case []string:
		for _, mv := range v {
			ip := net.ParseIP(mv)
			ips = append(ips, ip)
		}
	case []any:
		for _, mv := range v {
			switch mvv := mv.(type) {
			case string:
				ip := net.ParseIP(mvv)
				ips = append(ips, ip)
			case net.IP:
				ips = append(ips, mvv)
			}
		}
	}
	return ips, nil
}

func (c *Clients) mergeURIs(crt map[string]any, tmpURIs []*url.URL) ([]*url.URL, error) {
	uris := make([]*url.URL, 0)
	if tmpURIs != nil {
		uris = append(uris, tmpURIs...)
	}
	if crt["uri"] != nil {
		u, err := buildURIList(crt["uri"])
		if err != nil {
			return nil, err
		}
		uris = append(uris, u...)
		slices.SortFunc(uris, func(a, b *url.URL) int {
			return strings.Compare(a.String(), b.String())
		})
		return slices.CompactFunc(uris, func(e1, e2 *url.URL) bool {
			return e1.String() == e2.String()
		}), nil
	}
	return uris, nil
}

func buildURIList(crtUris any) ([]*url.URL, error) {
	uris := make([]*url.URL, 0)
	switch v := crtUris.(type) {
	case string:
		ul, err := url.Parse(v)
		if err != nil {
			return nil, err
		}
		uris = append(uris, ul)
	case []string:
		for _, mv := range v {
			ul, err := url.Parse(mv)
			if err != nil {
				return nil, err
			}
			uris = append(uris, ul)
		}
	case []any:
		for _, mv := range v {
			switch mvv := mv.(type) {
			case string:
				ul, err := url.Parse(mvv)
				if err != nil {
					return nil, err
				}
				uris = append(uris, ul)
			case url.URL:
				uris = append(uris, &mvv)
			}
		}
	}
	return uris, nil
}
