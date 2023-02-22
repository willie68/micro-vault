package groups

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services/storage"
)

const (
	ids = "group1"
)

func TestGroupBusiness(t *testing.T) {
	ast := assert.New(t)

	m := &storage.Memory{}
	err := m.Init()
	ast.Nil(err)

	g := Groups{
		stg: m,
	}

	ast.NotNil(g)

	gr := model.Group{
		Name:  ids,
		Label: map[string]string{"de": "Gruppe 1", "en": "group 1"},
	}

	id, err := g.AddGroup(gr)
	ast.Nil(err)
	ast.Equal(ids, id)

	ok := m.HasGroup(id)
	ast.True(ok)

	ok = g.DeleteGroup(id)
	ast.True(ok)

	ok = m.HasGroup(id)
	ast.False(ok)
}
