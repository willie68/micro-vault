package groups

import (
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/serror"
)

// Groups group management
type Groups struct {
	stg interfaces.Storage
}

// NewGroups creating a new groups business object
func NewGroups() (Groups, error) {
	gs := Groups{
		stg: do.MustInvoke[interfaces.Storage](nil),
	}
	do.ProvideValue[Groups](nil, gs)
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
		return "", serror.ErrAlreadyExists
	}
	id, err = g.stg.AddGroup(group)
	return
}

// UpdateGroup adding a new group to the service
func (g *Groups) UpdateGroup(group model.Group) (id string, err error) {
	if !g.stg.HasGroup(group.Name) {
		return "", serror.ErrNotExists
	}
	gr, ok := g.stg.GetGroup(group.Name)
	if !ok {
		return "", serror.ErrNotExists
	}
	// only the labels can be updated
	gr.Label = group.Label
	id, err = g.stg.AddGroup(*gr)
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
	// TODO check clients with that group?
	return ok
}
