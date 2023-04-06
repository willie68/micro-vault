package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/utils"
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

func TestRevokeToken(t *testing.T) {
	ast := assert.New(t)

	mem := &Memory{}
	err := mem.Init()
	ast.Nil(err)

	id := utils.GenerateID()

	ast.False(mem.IsRevoked(id))

	exp := time.Now().Add(1 * time.Second)
	err = mem.RevokeToken(id, exp)
	ast.Nil(err)

	ast.True(mem.IsRevoked(id))

	time.Sleep(2 * time.Second)
	mem.cleanup()

	ast.False(mem.IsRevoked(id))
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

	c := model.Client{
		Name:      "tester1",
		AccessKey: "12345678",
		Secret:    "yxcvb",
		Groups:    []string{"group1", "group2"},
		Key:       "PEMFILE",
	}

	n, err := mem.AddClient(c)
	ast.Nil(err)
	ast.Equal("tester1", n)

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

func TestCrudClient(t *testing.T) {
	ast := assert.New(t)

	mem := &Memory{}
	err := mem.Init()
	ast.Nil(err)
	cl := model.Client{
		Name:      "myname",
		AccessKey: "12345678",
		Secret:    "yxcvb",
		Groups:    []string{"group1"},
		KID:       "kid87654321",
	}
	n, err := mem.AddClient(cl)
	ast.Nil(err)
	ast.Equal(cl.Name, n)

	ok := mem.HasClient(cl.Name)
	ast.True(ok)

	n, err = mem.AddClient(cl)
	ast.NotNil(err)
	ast.Empty(n)

	a, ok := mem.AccessKey(cl.Name)
	ast.True(ok)
	ast.Equal(cl.AccessKey, a)

	cl.Secret = "bvcxy"

	err = mem.UpdateClient(cl)
	ast.Nil(err)

	ok = mem.HasClient(cl.Name)
	ast.True(ok)

	c2, ok := mem.GetClient(cl.AccessKey)
	ast.True(ok)
	ast.NotEmpty(c2.KID)
	ast.Equal(cl.Name, c2.Name)
	ast.Equal(cl.AccessKey, c2.AccessKey)
	ast.Equal(cl.Secret, c2.Secret)

	ok, err = mem.DeleteClient(cl.AccessKey)
	ast.Nil(err)
	ast.True(ok)

	ok = mem.HasClient(cl.Name)
	ast.False(ok)
}

func TestClientKID(t *testing.T) {
	ast := assert.New(t)

	mem := &Memory{}
	err := mem.Init()
	ast.Nil(err)
	cl := model.Client{
		Name:      "myname",
		AccessKey: "12345678",
		Secret:    "yxcvb",
		Groups:    []string{"group1"},
		KID:       "kid87654321",
	}
	n, err := mem.AddClient(cl)
	ast.Nil(err)
	ast.Equal(cl.Name, n)

	c2, ok := mem.ClientByKID(cl.KID)
	ast.True(ok)
	ast.NotNil(c2)
	ast.Equal(cl.AccessKey, c2.AccessKey)
}

func TestStoreEncryptKey(t *testing.T) {
	ast := assert.New(t)

	mem := &Memory{}
	err := mem.Init()
	ast.Nil(err)

	e := model.EncryptKey{
		ID:      "12345678",
		Alg:     "AES-256",
		Key:     "murks",
		Created: time.Now(),
		Group:   "group",
	}

	err = mem.StoreEncryptKey(e)
	ast.Nil(err)

	keys := make([]model.EncryptKey, 0)
	err = mem.ListEncryptKeys(0, 10, func(c model.EncryptKey) bool {
		keys = append(keys, c)
		return true
	})
	ast.Nil(err)
	ast.Equal(1, len(keys))

	ast.True(mem.HasEncryptKey(e.ID))

	e1, ok := mem.GetEncryptKey(e.ID)
	ast.True(ok)

	ast.Equal(e.ID, e1.ID)
	ast.Equal(e.Alg, e1.Alg)
	ast.Equal(e.Key, e1.Key)
	ast.Equal(e.Created, e1.Created)
	ast.Equal(e.Group, e1.Group)

	ok, err = mem.DeleteEncryptKey(e.ID)
	ast.Nil(err)
	ast.True(ok)

	e1, ok = mem.GetEncryptKey(e.ID)
	ast.False(ok)
	ast.Nil(e1)
}

func TestStoreDataCRUD(t *testing.T) {
	ast := assert.New(t)

	mem := &Memory{}
	err := mem.Init()
	ast.Nil(err)

	dm := model.Data{
		ID:      "12345678",
		Created: time.Now(),
		Group:   "group1",
		Payload: "dies ist eine Payload",
	}

	err = mem.StoreData(dm)
	ast.Nil(err)

	keys := make([]model.Data, 0)
	err = mem.ListData(0, 10, func(c model.Data) bool {
		keys = append(keys, c)
		return true
	})
	ast.Nil(err)
	ast.Equal(1, len(keys))

	dm2, ok := mem.GetData(dm.ID)
	ast.True(ok)
	ast.NotNil(dm2)
	ast.True(dmEqual(dm, *dm2))

	ok, err = mem.DeleteData(dm.ID)
	ast.True(ok)
	ast.Nil(err)

	dm2, ok = mem.GetData(dm.ID)
	ast.False(ok)
	ast.Nil(dm2)

	ok, err = mem.DeleteData(dm.ID)
	ast.False(ok)
	ast.Nil(err)
}

func TestStoreDataErrors(t *testing.T) {
	ast := assert.New(t)

	mem := &Memory{}
	err := mem.Init()
	ast.Nil(err)

	dm := model.Data{
		Created: time.Now(),
		Group:   "group1",
		Payload: "dies ist eine Payload",
	}

	err = mem.StoreData(dm)
	ast.NotNil(err)

}

func dmEqual(src, dst model.Data) bool {
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
