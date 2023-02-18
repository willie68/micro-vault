package storage

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/google/uuid"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
)

// Memory a memory based storage
type Memory struct {
	groups  map[string]model.Group
	clients map[string]model.Client
}

var _ interfaces.Storage = &Memory{}

// Init initialize the memory
func (m *Memory) Init() error {
	m.groups = make(map[string]model.Group)
	m.clients = make(map[string]model.Client)
	return nil
}

// AddGroup adding a group to internal store
func (m *Memory) AddGroup(g model.Group) (string, error) {
	if g.ID == "" {
		g.ID = uuid.New().String()
	}
	m.groups[g.Name] = g
	return g.ID, nil
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

// CreateClient creates a new client with defined groups
func (m *Memory) CreateClient(g []string) (*model.Client, error) {
	token := make([]byte, 16)
	_, err := rand.Read(token)
	if err != nil {
		return nil, err
	}
	c := model.Client{
		AccessKey: uuid.NewString(),
		Secret:    hex.EncodeToString(token),
		Groups:    g,
	}
	m.clients[c.AccessKey] = c
	return &c, nil
}

// DeleteClient delete a client
func (m *Memory) DeleteClient(a string) (bool, error) {
	_, ok := m.clients[a]
	if !ok {
		return false, nil
	}
	delete(m.clients, a)
	return true, nil
}
