package interfaces

import "github.com/willie68/micro-vault/internal/model"

// DoStorage dependency injection key name for storage
const DoStorage = "storage"

//go:generate mockery --name=Storage --outpkg=mocks --with-expecter
// Storage the storage interface definition
type Storage interface {
	Init() error
	Close() error

	HasGroup(n string) bool
	AddGroup(g model.Group) (id string, err error)
	DeleteGroup(n string) (ok bool, err error)
	GetGroups() ([]model.Group, error)
	GetGroup(n string) (*model.Group, bool)

	AddClient(c model.Client) (string, error)
	UpdateClient(c model.Client) error
	DeleteClient(a string) (ok bool, err error)
	ListClients(c func(g model.Client) bool) error
	GetClient(a string) (*model.Client, bool)
	ClientByKID(k string) (*model.Client, bool)
	AccessKey(n string) (string, bool)
	HasClient(n string) bool

	StoreEncryptKey(e model.EncryptKey) error
	GetEncryptKey(id string) (*model.EncryptKey, bool)
	ListEncryptKeys(s, l int64, c func(g model.EncryptKey) bool) error
}
