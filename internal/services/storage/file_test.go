package storage

import (
	"testing"
	"time"

	"github.com/samber/do"
	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/utils"
)

var stg interfaces.Storage

func testInit(ast *assert.Assertions) {
	s, err := NewFileStorage("../../../testdata/filestorage")
	ast.Nil(err)
	s1, _ := s.(*FileStorage)
	err = s1.clear()
	ast.Nil(err)
	stg = s
}

func TestNewFilestorage(t *testing.T) {
	ast := assert.New(t)
	testInit(ast)

	ast.NotNil(stg)

	stg = do.MustInvoke[interfaces.Storage](nil)
	ast.NotNil(stg)
	defer stg.Close()
}

func TestCreateFileStorage(t *testing.T) {
	ast := assert.New(t)
	testInit(ast)

	defer stg.Close()
}

func TestRevokeTokenFS(t *testing.T) {
	ast := assert.New(t)
	testInit(ast)
	defer stg.Close()

	id := utils.GenerateID()

	ast.False(stg.IsRevoked(id))

	exp := time.Now().Add(1 * time.Second)
	err := stg.RevokeToken(id, exp)
	ast.Nil(err)

	ast.True(stg.IsRevoked(id))

	time.Sleep(2 * time.Second)
	s, ok := stg.(*FileStorage)
	ast.True(ok)
	s.cleanup()

	ast.False(stg.IsRevoked(id))
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

	_, ok = stg.GetGroup(g.Name)
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
		Secret:    "e7d767cd1432145820669be6a60a912e",
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
		Secret:    "e7d767cd1432145820669be6a60a912e",
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

func TestClientKIDFS(t *testing.T) {
	ast := assert.New(t)

	testInit(ast)

	defer stg.Close()

	cl := model.Client{
		Name:      "myname",
		AccessKey: "12345678",
		Secret:    "e7d767cd1432145820669be6a60a912e",
		Groups:    []string{"group1"},
		KID:       "kid87654321",
	}
	n, err := stg.AddClient(cl)
	ast.Nil(err)
	ast.Equal(cl.Name, n)

	c2, ok := stg.ClientByKID(cl.KID)
	ast.True(ok)
	ast.NotNil(c2)
	ast.Equal(cl.AccessKey, c2.AccessKey)
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

	keys := make([]model.EncryptKey, 0)
	err = stg.ListEncryptKeys(0, 10, func(c model.EncryptKey) bool {
		keys = append(keys, c)
		return true
	})
	ast.Nil(err)
	ast.Equal(1, len(keys))

	ast.True(stg.HasEncryptKey(e.ID))

	e1, ok := stg.GetEncryptKey(e.ID)
	ast.True(ok)

	ast.Equal(e.ID, e1.ID)
	ast.Equal(e.Alg, e1.Alg)
	ast.Equal(e.Key, e1.Key)
	// ast.Equal(e.Created, e1.Created)
	ast.Equal(e.Group, e1.Group)

	ok, err = stg.DeleteEncryptKey(e.ID)
	ast.Nil(err)
	ast.True(ok)

	e1, ok = stg.GetEncryptKey(e.ID)
	ast.False(ok)
	ast.Nil(e1)
}

func TestStoreDataCRUDFS(t *testing.T) {
	ast := assert.New(t)

	testInit(ast)

	defer stg.Close()

	dm := model.Data{
		ID:      "12345678",
		Created: time.Now(),
		Group:   "group1",
		Payload: "dies ist eine Payload",
	}

	err := stg.StoreData(dm)
	ast.Nil(err)

	keys := make([]model.Data, 0)
	err = stg.ListData(0, 10, func(c model.Data) bool {
		keys = append(keys, c)
		return true
	})
	ast.Nil(err)
	ast.Equal(1, len(keys))

	dm2, ok := stg.GetData(dm.ID)
	ast.True(ok)
	ast.NotNil(dm2)
	ast.True(dmEqualFS(dm, *dm2))

	ok, err = stg.DeleteData(dm.ID)
	ast.True(ok)
	ast.Nil(err)

	dm2, ok = stg.GetData(dm.ID)
	ast.False(ok)
	ast.Nil(dm2)

	ok, err = stg.DeleteData(dm.ID)
	ast.False(ok)
	ast.Nil(err)
}

func TestStoreDataErrorsFS(t *testing.T) {
	ast := assert.New(t)

	testInit(ast)

	defer stg.Close()

	dm := model.Data{
		Created: time.Now(),
		Group:   "group1",
		Payload: "dies ist eine Payload",
	}

	err := stg.StoreData(dm)
	ast.NotNil(err)
}

func dmEqualFS(src, dst model.Data) bool {
	if src.ID != dst.ID {
		return false
	}
	if src.Group != dst.Group {
		return false
	}
	if src.Payload != dst.Payload {
		return false
	}
	if !src.Created.Equal(dst.Created) {
		return false
	}
	if !src.Expires.Equal(dst.Expires) {
		return false
	}
	return true
}
