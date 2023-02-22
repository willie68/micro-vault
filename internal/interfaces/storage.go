package interfaces

import "github.com/willie68/micro-vault/internal/model"

//go:generate mockery --name=Storage --outpkg=mocks --with-expecter
// Storage the storage interface definition
type Storage interface {
	Init() error
	HasGroup(n string) bool
	AddGroup(g model.Group) (id string, err error)
	DeleteGroup(n string) (ok bool, err error)
	GetGroups() ([]model.Group, error)
	GetGroup(n string) (*model.Group, bool)

	CreateClient(n string, g []string) (*model.Client, error)
	AddClient(c model.Client) (string, error)
	UpdateClient(c model.Client) error
	DeleteClient(a string) (ok bool, err error)
	ListClients(c func(g model.Client) bool) error
	GetClient(a string) (*model.Client, bool)
	HasClient(n string) bool
}
