package storage

import (
	"testing"
	"time"

	"github.com/samber/do"
	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
)

var stg interfaces.Storage

func testInit(ast *assert.Assertions) {
	s, err := NewFileStorage("../../../testdata/filestorage")
	ast.Nil(err)
	s1, _ := s.(*FileStorage)
	s1.clear()
	stg = s
}

func TestNewFilestorage(t *testing.T) {
	ast := assert.New(t)
	testInit(ast)

	ast.NotNil(stg)

	stg = do.MustInvokeNamed[interfaces.Storage](nil, interfaces.DoStorage)
	ast.NotNil(stg)
	defer stg.Close()
}

func TestCreateFileStorage(t *testing.T) {
	ast := assert.New(t)
	testInit(ast)

	defer stg.Close()
}

func TestGroupCRUDFS(t *testing.T) {
	ast := assert.New(t)
	testInit(ast)
	defer stg.Close()

	gs, err := stg.GetGroups()
	ast.Nil(err)
	ast.Equal(0, len(gs))

	g := model.Group{
		Name: ids,
		Label: map[string]string{
			"de": "Gruppe 1",
			"en": "Group 1",
		},
	}

	id, err := stg.AddGroup(g)
	ast.Nil(err)
	ast.Equal(ids, id)

	gs, err = stg.GetGroups()
	ast.Nil(err)
	ast.Equal(1, len(gs))

	ok := stg.HasGroup(id)
	ast.True(ok)

	dg, ok := stg.GetGroup(g.Name)
	ast.True(ok)
	ast.Equal(g.Name, dg.Name)

	ok, err = stg.DeleteGroup(id)
	ast.Nil(err)
	ast.True(ok)

	dg, ok = stg.GetGroup(g.Name)
	ast.False(ok)
}

func TestUnknownGroupFS(t *testing.T) {
	ast := assert.New(t)
	testInit(ast)
	defer stg.Close()

	ok := stg.HasGroup("muck")
	ast.False(ok)

	dg, ok := stg.GetGroup("muck")
	ast.False(ok)
	ast.Nil(dg)
}

func TestClientStorageFS(t *testing.T) {
	ast := assert.New(t)
	testInit(ast)
	defer stg.Close()

	cl := make([]model.Client, 0)
	err := stg.ListClients(func(c model.Client) bool {
		cl = append(cl, c)
		return true
	})
	ast.Nil(err)
	ast.Equal(0, len(cl))

	c := model.Client{
		Name:      "tester1",
		AccessKey: "12345678",
		Secret:    "yxcvb",
		Groups:    []string{"group1", "group2"},
		Key:       "PEMFILE",
	}

	n, err := stg.AddClient(c)
	ast.Nil(err)
	ast.Equal("tester1", n)

	cl = make([]model.Client, 0)
	err = stg.ListClients(func(c model.Client) bool {
		cl = append(cl, c)
		return true
	})
	ast.Nil(err)
	ast.Equal(1, len(cl))

	dc, ok := stg.GetClient(c.AccessKey)
	ast.True(ok)
	ast.Equal(c.AccessKey, dc.AccessKey)
	ast.Equal(c.Secret, dc.Secret)

	dc, ok = stg.GetClient("muck")
	ast.False(ok)
	ast.Nil(dc)
}

func TestAddClientFS(t *testing.T) {
	ast := assert.New(t)
	testInit(ast)

	defer stg.Close()

	cl := model.Client{
		Name:      "myname",
		AccessKey: "12345678",
		Secret:    "yxcvb",
		Groups:    []string{"group1"},
	}
	n, err := stg.AddClient(cl)
	ast.Nil(err)
	ast.Equal(cl.Name, n)

	ok := stg.HasClient(cl.Name)
	ast.True(ok)

	n, err = stg.AddClient(cl)
	ast.NotNil(err)
	ast.Empty(n)

	a, ok := stg.AccessKey(cl.Name)
	ast.True(ok)
	ast.Equal(cl.AccessKey, a)
}

func TestStoreEncryptKeyFS(t *testing.T) {
	ast := assert.New(t)
	testInit(ast)

	defer stg.Close()

	e := model.EncryptKey{
		ID:      "12345678",
		Alg:     "AES-256",
		Key:     "murks",
		Created: time.Now(),
		Group:   "group",
	}

	err := stg.StoreEncryptKey(e)
	ast.Nil(err)

	e1, ok := stg.GetEncryptKey(e.ID)
	ast.True(ok)

	ast.Equal(e.ID, e1.ID)
	ast.Equal(e.Alg, e1.Alg)
	ast.Equal(e.Key, e1.Key)
	//ast.Equal(e.Created, e1.Created)
	ast.Equal(e.Group, e1.Group)
}
