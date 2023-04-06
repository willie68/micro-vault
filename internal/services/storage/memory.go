package storage

import (
	"errors"
	"sync"
	"time"

	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services"
)

// Memory a memory based storage
type Memory struct {
	groups  map[string]model.Group
	clients sync.Map
	keys    sync.Map
	revokes sync.Map
	datas   sync.Map
	ticker  *time.Ticker
	tckDone chan bool
}

var _ interfaces.Storage = &Memory{}

// NewMemory creates a new memory storage
func NewMemory() (interfaces.Storage, error) {
	stg := Memory{}
	err := stg.Init()
	if err != nil {
		return nil, err
	}
	do.ProvideNamedValue[interfaces.Storage](nil, interfaces.DoStorage, &stg)
	return &stg, nil
}

// Init initialize the memory
func (m *Memory) Init() error {
	m.groups = make(map[string]model.Group)
	m.clients = sync.Map{}
	m.keys = sync.Map{}
	m.revokes = sync.Map{}
	m.datas = sync.Map{}
	m.tckDone = make(chan bool)
	m.ticker = time.NewTicker(1 * time.Minute)

	go func() {
		for {
			select {
			case <-m.tckDone:
				return
			case <-m.ticker.C:
				m.cleanup()
			}
		}
	}()

	return nil
}

// Close closes the memory, freeing all resources
func (m *Memory) Close() error {
	m.groups = make(map[string]model.Group)
	m.clients = sync.Map{}
	m.keys = sync.Map{}
	m.revokes = sync.Map{}
	do.ShutdownNamed(nil, interfaces.DoStorage)
	m.ticker.Stop()
	m.tckDone <- true
	return nil
}

func (m *Memory) cleanup() {
	m.revokes.Range(func(key, value any) bool {
		exp := value.(time.Time)
		if time.Now().After(exp) {
			m.revokes.Delete(key)
		}
		return true
	})
}

// RevokeToken set this token id to the revoked token
func (m *Memory) RevokeToken(id string, exp time.Time) error {
	if time.Now().After(exp) {
		return nil
	}
	m.revokes.Store(id, exp)
	return nil
}

// IsRevoked checking if an token id is already revoked
func (m *Memory) IsRevoked(id string) bool {
	_, ok := m.revokes.Load(id)
	return ok
}

// AddGroup adding a group to internal store
func (m *Memory) AddGroup(g model.Group) (string, error) {
	m.groups[g.Name] = g
	return g.Name, nil
}

// HasGroup checks if a group is present
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

// ClientByKID returning a client by it's kid of the private key
func (m *Memory) ClientByKID(k string) (*model.Client, bool) {
	var ak string
	m.clients.Range(func(key, value any) bool {
		cl := value.(model.Client)
		if cl.KID == k {
			ak = cl.AccessKey
			return false
		}
		return true
	})
	return m.GetClient(ak)
}

// AccessKey returning the access key of client with name
func (m *Memory) AccessKey(n string) (string, bool) {
	var ak string
	m.clients.Range(func(key, value any) bool {
		cl := value.(model.Client)
		if cl.Name == n {
			ak = cl.AccessKey
			return false
		}
		return true
	})
	return ak, ak != ""
}

// StoreEncryptKey stores the encrypt keys
func (m *Memory) StoreEncryptKey(e model.EncryptKey) error {
	if e.ID == "" {
		return services.ErrMissingID
	}
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

// HasEncryptKey checks if a key is present
func (m *Memory) HasEncryptKey(id string) bool {
	_, ok := m.keys.Load(id)
	return ok
}

// ListEncryptKeys list all clients via callback function
func (m *Memory) ListEncryptKeys(s, l int64, c func(c model.EncryptKey) bool) error {
	var cnt int64
	cnt = 0
	m.keys.Range(func(key, value any) bool {
		cnt++
		n := true
		if cnt > s && cnt < (s+l) {
			cl := value.(model.EncryptKey)
			n = c(cl)
		}
		return n
	})
	return nil
}

// DeleteEncryptKey deletes the encrytion key
func (m *Memory) DeleteEncryptKey(id string) (bool, error) {
	_, ok := m.keys.LoadAndDelete(id)
	return ok, nil
}

// StoreData stores the data
func (m *Memory) StoreData(data model.Data) error {
	if data.ID == "" {
		return services.ErrMissingID
	}
	m.datas.Store(data.ID, data)
	return nil
}

// GetData retrieving the data model
func (m *Memory) GetData(id string) (*model.Data, bool) {
	k, ok := m.datas.Load(id)
	if !ok {
		return nil, false
	}
	d := k.(model.Data)
	return &d, true
}

// DeleteData removes the data model from storage
func (m *Memory) DeleteData(id string) (bool, error) {
	_, ok := m.datas.LoadAndDelete(id)
	return ok, nil
}

// ListData list all datas via callback function
func (m *Memory) ListData(s, l int64, c func(c model.Data) bool) error {
	var cnt int64
	cnt = 0
	m.datas.Range(func(key, value any) bool {
		cnt++
		n := true
		if cnt > s && cnt < (s+l) {
			cl := value.(model.Data)
			n = c(cl)
		}
		return n
	})
	return nil
}
