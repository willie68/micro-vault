package storage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
)

// Memory a memory based storage
type Memory struct {
	groups  map[string]model.Group
	clients sync.Map
	keys    sync.Map
}

var _ interfaces.Storage = &Memory{}

// NewMemory creates a new memory storage
func NewMemory() (interfaces.Storage, error) {
	stg := Memory{}
	err := stg.Init()
	if err != nil {
		return nil, err
	}
	do.ProvideNamedValue[interfaces.Storage](nil, "storage", &stg)
	return &stg, nil
}

// Init initialize the memory
func (m *Memory) Init() error {
	m.groups = make(map[string]model.Group)
	m.clients = sync.Map{}
	return nil
}

// AddGroup adding a group to internal store
func (m *Memory) AddGroup(g model.Group) (string, error) {
	m.groups[g.Name] = g
	return g.Name, nil
}

// HasGroup deletes a group if present
func (m *Memory) HasGroup(n string) bool {
	_, ok := m.groups[n]
	return ok
}

// DeleteGroup deletes a group if present
func (m *Memory) DeleteGroup(n string) (bool, error) {
	_, ok := m.groups[n]
	if !ok {
		return false, nil
	}
	delete(m.groups, n)
	return true, nil
}

// GetGroups getting a list of all groups defined
func (m *Memory) GetGroups() ([]model.Group, error) {
	gs := make([]model.Group, 0)
	for _, v := range m.groups {
		gs = append(gs, v)
	}
	return gs, nil
}

// GetGroup getting a single group
func (m *Memory) GetGroup(n string) (*model.Group, bool) {
	g, ok := m.groups[n]
	if !ok {
		return nil, false
	}
	return &g, ok
}

// HasClient checks if a client is present
func (m *Memory) HasClient(n string) bool {
	f := false
	m.clients.Range(func(key, value any) bool {
		c, _ := value.(model.Client)
		if c.Name == n {
			f = true
			return false
		}
		if c.AccessKey == n {
			f = true
			return false
		}
		return true
	})
	return f
}

// CreateClient creates a new client with defined groups
func (m *Memory) CreateClient(n string, g []string) (*model.Client, error) {
	token := make([]byte, 16)
	_, err := rand.Read(token)
	if err != nil {
		return nil, err
	}
	c := model.Client{
		Name:      n,
		AccessKey: uuid.NewString(),
		Secret:    hex.EncodeToString(token),
		Groups:    g,
	}
	m.clients.Store(c.AccessKey, c)
	return &c, nil
}

// AddClient adding the client to the internal storage
func (m *Memory) AddClient(c model.Client) (string, error) {
	_, ok := m.clients.Load(c.AccessKey)
	if ok {
		return "", errors.New("client already exists")
	}
	f := false
	m.clients.Range(func(key, value any) bool {
		cl, _ := value.(model.Client)
		if cl.Name == c.Name {
			f = true
			return false
		}
		return true
	})
	if f {
		return "", errors.New("client already exists")
	}
	m.clients.Store(c.AccessKey, c)
	return c.Name, nil
}

// UpdateClient adding the client to the internal storage
func (m *Memory) UpdateClient(c model.Client) error {
	m.clients.Store(c.AccessKey, c)
	return nil
}

// DeleteClient delete a client
func (m *Memory) DeleteClient(a string) (bool, error) {
	_, ok := m.clients.LoadAndDelete(a)
	return ok, nil
}

// ListClients list all clients via callback function
func (m *Memory) ListClients(c func(c model.Client) bool) error {
	m.clients.Range(func(key, value any) bool {
		cl := value.(model.Client)
		return c(cl)
	})
	return nil
}

// GetClient returning a client with an access key
func (m *Memory) GetClient(a string) (*model.Client, bool) {
	v, ok := m.clients.Load(a)
	if !ok {
		return nil, false
	}
	c := v.(model.Client)
	return &c, ok
}

// StoreEncryptKey stores the encrypt keys
func (m *Memory) StoreEncryptKey(e model.EncryptKey) error {
	m.keys.Store(e.ID, e)
	return nil
}

// GetEncryptKey stores the encrypt keys
func (m *Memory) GetEncryptKey(id string) (*model.EncryptKey, bool) {
	k, ok := m.keys.Load(id)
	if !ok {
		return nil, false
	}
	e := k.(model.EncryptKey)
	return &e, true
}
