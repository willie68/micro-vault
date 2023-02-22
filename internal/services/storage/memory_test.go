package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/model"
)

const (
	ids = "group1"
)

func TestCreateMemoryStorage(t *testing.T) {
	ast := assert.New(t)

	mem := &Memory{}
	err := mem.Init()
	ast.Nil(err)
}

func TestGroupCRUD(t *testing.T) {
	ast := assert.New(t)

	mem := &Memory{}
	err := mem.Init()
	ast.Nil(err)

	gs, err := mem.GetGroups()
	ast.Nil(err)
	ast.Equal(0, len(gs))

	g := model.Group{
		Name: ids,
		Label: map[string]string{
			"de": "Gruppe 1",
			"en": "Group 1",
		},
	}

	id, err := mem.AddGroup(g)
	ast.Nil(err)
	ast.Equal(ids, id)

	gs, err = mem.GetGroups()
	ast.Nil(err)
	ast.Equal(1, len(gs))

	ok := mem.HasGroup(id)
	ast.True(ok)

	dg, ok := mem.GetGroup(g.Name)
	ast.True(ok)
	ast.Equal(g.Name, dg.Name)

	ok, err = mem.DeleteGroup(id)
	ast.Nil(err)
	ast.True(ok)

	dg, ok = mem.GetGroup(g.Name)
	ast.False(ok)
}

func TestUnknownGroup(t *testing.T) {
	ast := assert.New(t)

	mem := &Memory{}
	err := mem.Init()
	ast.Nil(err)

	ok := mem.HasGroup("muck")
	ast.False(ok)

	dg, ok := mem.GetGroup("muck")
	ast.False(ok)
	ast.Nil(dg)
}

func TestClientStorage(t *testing.T) {
	ast := assert.New(t)

	mem := &Memory{}
	err := mem.Init()
	ast.Nil(err)
	cl := make([]model.Client, 0)
	err = mem.ListClients(func(c model.Client) bool {
		cl = append(cl, c)
		return true
	})
	ast.Nil(err)
	ast.Equal(0, len(cl))

	c, err := mem.CreateClient("tester1", []string{"group1", "group2"})
	ast.Nil(err)
	ast.NotEmpty(c.AccessKey)
	ast.NotEmpty(c.Secret)

	cl = make([]model.Client, 0)
	err = mem.ListClients(func(c model.Client) bool {
		cl = append(cl, c)
		return true
	})
	ast.Nil(err)
	ast.Equal(1, len(cl))

	dc, ok := mem.GetClient(c.AccessKey)
	ast.True(ok)
	ast.Equal(c.AccessKey, dc.AccessKey)
	ast.Equal(c.Secret, dc.Secret)

	dc, ok = mem.GetClient("muck")
	ast.False(ok)
	ast.Nil(dc)
}

func TestAddClient(t *testing.T) {
	ast := assert.New(t)

	mem := &Memory{}
	err := mem.Init()
	ast.Nil(err)
	cl := model.Client{
		Name:      "myname",
		AccessKey: "12345678",
		Secret:    "yxcvb",
		Groups:    []string{"group1"},
	}
	n, err := mem.AddClient(cl)
	ast.Nil(err)
	ast.Equal(cl.Name, n)

	ok := mem.HasClient(cl.Name)
	ast.True(ok)

	n, err = mem.AddClient(cl)
	ast.NotNil(err)
	ast.Empty(n)
}
