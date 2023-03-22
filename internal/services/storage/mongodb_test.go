package storage

import (
	"testing"
	"time"

	"github.com/samber/do"
	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services/keyman"
)

const (
	keyfile1 = "../../../testdata/private1.pem"
)

var mgo *MongoStorage

func mongoInit() {
	do.ShutdownNamed(nil, config.DoServiceConfig)
	do.ShutdownNamed(nil, keyman.DoKeyman)

	cfg := config.Config{
		Service: config.Service{
			PrivateKey: keyfile1,
		},
	}
	cfg.Provide()

	_, err := keyman.NewKeyman()
	if err != nil {
		panic(err)
	}

	mem, err := prepareMongoClient(
		MongoDBConfig{
			Hosts:        []string{"127.0.0.1:27017"},
			Database:     "microvault",
			AuthDatabase: "microvault",
			Username:     "microvault",
			Password:     "yxcvb",
		},
	)
	if err != nil {
		panic(err)
	}
	err = mem.Init()
	if err != nil {
		panic(err)
	}
	err = mem.clear()
	if err != nil {
		panic(err)
	}
	err = mem.Init()
	if err != nil {
		panic(err)
	}
	mgo = mem
}

func TestMongoGroupCRUD(t *testing.T) {
	ast := assert.New(t)

	mongoInit()

	gs, err := mgo.GetGroups()
	ast.Nil(err)
	ast.Equal(0, len(gs))

	g := model.Group{
		Name: ids,
		Label: map[string]string{
			"de": "Gruppe 1",
			"en": "Group 1",
		},
	}

	id, err := mgo.AddGroup(g)
	ast.Nil(err)
	ast.Equal(ids, id)

	gs, err = mgo.GetGroups()
	ast.Nil(err)
	ast.Equal(1, len(gs))

	ok := mgo.HasGroup(id)
	ast.True(ok)

	dg, ok := mgo.GetGroup(g.Name)
	ast.True(ok)
	ast.Equal(g.Name, dg.Name)

	ok, err = mgo.DeleteGroup(id)
	ast.Nil(err)
	ast.True(ok)

	dg, ok = mgo.GetGroup(g.Name)
	ast.False(ok)
}

func TestMongoUnknownGroup(t *testing.T) {
	ast := assert.New(t)

	mongoInit()

	ok := mgo.HasGroup("muck")
	ast.False(ok)

	dg, ok := mgo.GetGroup("muck")
	ast.False(ok)
	ast.Nil(dg)
}

func TestMongoClientStorage(t *testing.T) {
	ast := assert.New(t)

	mongoInit()

	cl := make([]model.Client, 0)
	err := mgo.ListClients(func(c model.Client) bool {
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

	n, err := mgo.AddClient(c)
	ast.Nil(err)
	ast.Equal("tester1", n)

	cl = make([]model.Client, 0)
	err = mgo.ListClients(func(c model.Client) bool {
		cl = append(cl, c)
		return true
	})
	ast.Nil(err)
	ast.Equal(1, len(cl))

	dc, ok := mgo.GetClient(c.AccessKey)
	ast.True(ok)
	ast.Equal(c.AccessKey, dc.AccessKey)
	ast.Equal(c.Secret, dc.Secret)

	dc, ok = mgo.GetClient("muck")
	ast.False(ok)
	ast.Nil(dc)
}

func TestMongoCrudClient(t *testing.T) {
	ast := assert.New(t)
	mongoInit()

	cl := model.Client{
		Name:      "myname",
		AccessKey: "12345678",
		Secret:    "yxcvb",
		Groups:    []string{"group1"},
		KID:       "kid87654321",
	}
	n, err := mgo.AddClient(cl)
	ast.Nil(err)
	ast.Equal(cl.Name, n)

	ok := mgo.HasClient(cl.Name)
	ast.True(ok)

	n, err = mgo.AddClient(cl)
	ast.NotNil(err)
	ast.Empty(n)

	a, ok := mgo.AccessKey(cl.Name)
	ast.True(ok)
	ast.Equal(cl.AccessKey, a)

	cl.Secret = "bvcxy"

	err = mgo.UpdateClient(cl)
	ast.Nil(err)

	ok = mgo.HasClient(cl.Name)
	ast.True(ok)

	c2, ok := mgo.GetClient(cl.AccessKey)
	ast.True(ok)
	ast.NotEmpty(c2.KID)
	ast.Equal(cl.Name, c2.Name)
	ast.Equal(cl.AccessKey, c2.AccessKey)
	ast.Equal(cl.Secret, c2.Secret)

	ok, err = mgo.DeleteClient(cl.AccessKey)
	ast.Nil(err)
	ast.True(ok)

	ok = mgo.HasClient(cl.Name)
	ast.False(ok)
}

func TestMongoClientKID(t *testing.T) {
	ast := assert.New(t)

	mongoInit()

	cl := model.Client{
		Name:      "myname",
		AccessKey: "12345678",
		Secret:    "yxcvb",
		Groups:    []string{"group1"},
		KID:       "kid87654321",
	}
	n, err := mgo.AddClient(cl)
	ast.Nil(err)
	ast.Equal(cl.Name, n)

	c2, ok := mgo.ClientByKID(cl.KID)
	ast.True(ok)
	ast.NotNil(c2)
	ast.Equal(cl.AccessKey, c2.AccessKey)
}

func TestMongoStoreEncryptKey(t *testing.T) {
	ast := assert.New(t)

	mongoInit()

	e := model.EncryptKey{
		ID:      "12345678",
		Alg:     "AES-256",
		Key:     "murks",
		Created: time.Now(),
		Group:   "group",
	}

	err := mgo.StoreEncryptKey(e)
	ast.Nil(err)

	keys := make([]model.EncryptKey, 0)
	err = mgo.ListEncryptKeys(0, 10, func(c model.EncryptKey) bool {
		keys = append(keys, c)
		return true
	})
	ast.Nil(err)
	ast.Equal(1, len(keys))

	e1, ok := mgo.GetEncryptKey(e.ID)
	ast.True(ok)

	ast.Equal(e.ID, e1.ID)
	ast.Equal(e.Alg, e1.Alg)
	ast.Equal(e.Key, e1.Key)
	//ast.Equal(e.Created, e1.Created)
	ast.Equal(e.Group, e1.Group)
}
