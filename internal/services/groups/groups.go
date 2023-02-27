package groups

import (
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services"
)

// DoGroups dependency injection key name for groups
const DoGroups = "groups"

// Groups group management
type Groups struct {
	stg interfaces.Storage
}

// NewGroups creating a new groups business object
func NewGroups() (Groups, error) {
	gs := Groups{
		stg: do.MustInvokeNamed[interfaces.Storage](nil, interfaces.DoStorage),
	}
	do.ProvideNamedValue[Groups](nil, DoGroups, gs)
	return gs, nil
}

// Init initialize the group management
func (g *Groups) Init(s interfaces.Storage) error {
	g.stg = s
	return nil
}

// AddGroup adding a new group to the service
func (g *Groups) AddGroup(group model.Group) (id string, err error) {
	if g.stg.HasGroup(group.Name) {
		return "", services.ErrAlreadyExists
	}
	id, err = g.stg.AddGroup(group)
	return
}

// DeleteGroup deleting a group
func (g *Groups) DeleteGroup(name string) bool {
	if !g.stg.HasGroup(name) {
		return true
	}
	ok, err := g.stg.DeleteGroup(name)
	if err != nil {
		return false
	}
	err = g.stg.ListClients(func(g model.Client) bool {
		return true
	})
	return ok
}
