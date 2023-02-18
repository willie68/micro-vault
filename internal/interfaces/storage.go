package interfaces

import "github.com/willie68/micro-vault/internal/model"

// Storage the storage interface definition
type Storage interface {
	Init() error
	AddGroup(g model.Group) (id string, err error)
	DeleteGroup(n string) (ok bool, err error)

	CreateClient(g []string) (*model.Client, error)
	DeleteClient(a string) (ok bool, err error)
}
