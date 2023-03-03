package groups

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services/storage"
)

const (
	ids = "group1"
)

var (
	stg interfaces.Storage
)

func init() {
	s, err := storage.NewMemory()
	if err != nil {
		panic(err)
	}
	stg = s
}

func TestGroupDependency(t *testing.T) {
	ast := assert.New(t)

	g, err := NewGroups()
	ast.Nil(err)
	ast.NotNil(g)
}

func TestGroupBusiness(t *testing.T) {
	ast := assert.New(t)

	g := Groups{
		stg: stg,
	}

	ast.NotNil(g)

	gr := model.Group{
		Name:  ids,
		Label: map[string]string{"de": "Gruppe 1", "en": "group 1"},
	}

	id, err := g.AddGroup(gr)
	ast.Nil(err)
	ast.Equal(ids, id)

	ok := stg.HasGroup(id)
	ast.True(ok)

	ok = g.DeleteGroup(id)
	ast.True(ok)

	ok = stg.HasGroup(id)
	ast.False(ok)
}
