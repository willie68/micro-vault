// Package mongodb using a mongo db as a index engine for the search
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/dgraph-io/badger/v4"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/logging"
	log "github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services/keyman"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	driver "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// checking interface compatibility
var _ interfaces.Storage = &MongoStorage{}

// MongoDBConfig configuration for a mongodb
type MongoDBConfig struct {
	Hosts        []string `yaml:"hosts" json:"hosts"`
	Database     string   `yaml:"database" json:"database"`
	AuthDatabase string   `yaml:"authdatabase" json:"authdatabase"`
	Username     string   `yaml:"username" json:"username"`
	Password     string   `yaml:"password" json:"password"`
}

// MongoStorage the struct for te storage interface
type MongoStorage struct {
	mcnfg    MongoDBConfig
	client   *driver.Client
	database *driver.Database
	ctx      context.Context
	knm      keyman.Keyman
}

// NewMongoStorage initialize the mongo db for usage in this service
func NewMongoStorage(mcnfg MongoDBConfig) (interfaces.Storage, error) {
	if len(mcnfg.Hosts) == 0 {
		return errors.New("no mongo hosts found. check config")
	}
	rb := bson.NewRegistryBuilder()
	rb.RegisterTypeMapEntry(bsontype.EmbeddedDocument, reflect.TypeOf(bson.M{}))

	uri := fmt.Sprintf("mongodb://%s", mcnfg.Hosts[0])
	opts := options.Client().SetRegistry(rb.Build())
	opts.ApplyURI(uri)
	if mcnfg.Username != "" {
		opts.Auth = &options.Credential{
			Username:   mcnfg.Username,
			Password:   mcnfg.Password,
			AuthSource: mcnfg.AuthDatabase}
	}
	ctx := context.TODO()
	client, err := driver.Connect(ctx, opts)
	if err != nil {
		log.Logger.Errorf("%v", err)
		return err
	}

	database := client.Database(mcnfg.Database)

	stg := MongoStorage{
		mcnfg:    cfg,
		client:   client,
		database: database,
		ctx:      ctx,
		knm:      do.MustInvokeNamed[keyman.Keyman](nil, keyman.DoKeyman),
	}
	do.ProvideNamedValue[interfaces.Storage](nil, interfaces.DoStorage, &stg)
	return stg, nil
}

// Init initialize the connection to the mongo db. cerate collections with index as needed
func (m *MongoStorage) Init() error {
	// TODO create collections with indexes
	return nil
}

// Close closing the connection to mongo
func (m *MongoStorage) Close() error {
	m.client.Disconnect(m.ctx)
	return nil
}

// AddGroup adding a group to internal store
func (m *MongoStorage) AddGroup(g model.Group) (string, error) {
	err := f.update(groupKey, g.Name, g)
	if err != nil {
		return "", err
	}
	return g.Name, nil
}

// HasGroup checks if a group is present
func (m *MongoStorage) HasGroup(n string) (found bool) {
	return f.has(groupKey, n)
}

// DeleteGroup deletes a group if present
func (m *MongoStorage) DeleteGroup(n string) (bool, error) {
	err := f.delete(groupKey, n)
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetGroups getting a list of all groups defined
func (m *MongoStorage) GetGroups() ([]model.Group, error) {
	gs := make([]model.Group, 0)
	err := f.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(groupKey)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(v []byte) error {
				var g model.Group
				err := json.Unmarshal(v, &g)
				if err != nil {
					return err
				}
				gs = append(gs, g)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gs, nil
}

// GetGroup getting a single group
func (m *MongoStorage) GetGroup(n string) (*model.Group, bool) {
	var g model.Group
	ok := f.get(groupKey, n, &g)
	if !ok {
		return nil, false
	}
	return &g, true
}

// HasClient checks if a client is present
func (m *MongoStorage) HasClient(n string) bool {
	found := false
	err := f.ListClients(func(g model.Client) bool {
		if g.Name == n {
			found = true
			return false
		}
		return true
	})
	if err != nil {
		log.Logger.Errorf("error has client: %v", err)
	}
	return found
}

// AddClient adding the client to the internal storage
func (m *MongoStorage) AddClient(c model.Client) (string, error) {
	if f.has(clientKey, c.AccessKey) {
		return "", errors.New("client already exists")
	}
	found := false
	err := f.ListClients(func(g model.Client) bool {
		if g.Name == c.Name {
			found = true
			return false
		}
		return true
	})
	if found {
		return "", errors.New("client already exists")
	}
	err = f.update(clientKey, c.AccessKey, c)
	if err != nil {
		return "", err
	}
	return c.Name, nil
}

// UpdateClient adding the client to the internal storage
func (m *MongoStorage) UpdateClient(c model.Client) error {
	err := f.update(clientKey, c.AccessKey, c)
	if err != nil {
		return err
	}
	return nil
}

// DeleteClient delete a client
func (m *MongoStorage) DeleteClient(a string) (bool, error) {
	err := f.delete(clientKey, a)
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListClients list all clients via callback function
func (m *MongoStorage) ListClients(c func(g model.Client) bool) error {
	err := f.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(clientKey)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			var g model.Client
			valCopy, err := item.ValueCopy(nil)
			err = json.Unmarshal(valCopy, &g)
			if err != nil {
				return err
			}
			if !c(g) {
				break
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

// GetClient returning a client with an access key
func (m *MongoStorage) GetClient(a string) (*model.Client, bool) {
	var cl model.Client
	ok := f.get(clientKey, a, &cl)
	if !ok {
		return nil, false
	}
	return &cl, true
}

// ClientByKID returning a client by it's kid of the private key
func (m *MongoStorage) ClientByKID(k string) (*model.Client, bool) {
	var c *model.Client
	err := f.ListClients(func(g model.Client) bool {
		if g.KID == k {
			c = &g
			return false
		}
		return true
	})
	if err != nil {
		return nil, false
	}
	if c == nil {
		return nil, false
	}
	return c, true
}

// AccessKey returning the access key of client with name
func (m *MongoStorage) AccessKey(n string) (string, bool) {
	key := ""
	found := false
	err := f.ListClients(func(g model.Client) bool {
		if g.Name == n {
			found = true
			key = g.AccessKey
			return false
		}
		return true
	})
	if err != nil {
		log.Logger.Errorf("error has client: %v", err)
	}
	if !found {
		return "", false
	}
	return key, true
}

// StoreEncryptKey stores the encrypt keys
func (m *MongoStorage) StoreEncryptKey(e model.EncryptKey) error {
	err := f.update(encryptionKey, e.ID, e)
	if err != nil {
		return err
	}
	return nil
}

// GetEncryptKey stores the encrypt keys
func (m *MongoStorage) GetEncryptKey(id string) (*model.EncryptKey, bool) {
	var e model.EncryptKey
	ok := f.get(encryptionKey, id, &e)
	if !ok {
		return nil, false
	}
	return &e, true
}

func (m *MongoStorage) update(t, k string, p any) error {
	v, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return f.db.Update(func(txn *badger.Txn) error {
		err := txn.Set(buildKey(t, k), v)
		return err
	})
}

func (m *MongoStorage) has(t, k string) (found bool) {
	key := string(buildKey(t, k))
	err := f.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		prefix := []byte(t)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			found = string(item.Key()) == key
			if found {
				it.Close()
			}
			return nil
		}
		return nil
	})
	if err != nil {
		log.Logger.Errorf("error checking entry: %v", err)
		return false
	}
	return
}

func (m *MongoStorage) get(t, k string, v any) bool {
	key := buildKey(t, k)
	err := f.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		valCopy, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		err = json.Unmarshal(valCopy, v)
		return err
	})
	if err != nil {
		log.Logger.Errorf("error getting entry: %v", err)
		return false
	}
	return true
}

func (m *MongoStorage) delete(t, k string) error {
	key := buildKey(t, k)
	err := f.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
	if err != nil {
		log.Logger.Errorf("error deleting entry: %v", err)
		return err
	}
	return nil
}

func (m *MongoStorage) clear() error {
	cols, err := m.database.ListCollectionNames(m.ctx, nil, options.ListCollectionsOptions.NameOnly)
	if err != nil {
		return err
	}
	for _, col := range cols {
		dc := m.database.Collection(col)
		err := dc.Drop(m.ctx)
		if err != nil {
			logging.Logger.Errorf("drop collection error: %v", err)
		}
	}
	return nil
}
