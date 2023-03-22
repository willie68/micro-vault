package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/dgraph-io/badger/v4"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/interfaces"
	log "github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/internal/model"
)

// FileStorage storage engine on file system
type FileStorage struct {
	path string
	db   *badger.DB
}

const (
	groupKey      = "group"
	clientKey     = "client"
	nameKey       = "name"
	encryptionKey = "encryption"
)

var _ interfaces.Storage = &FileStorage{}

// NewFileStorage creates a new memory storage
func NewFileStorage(p string) (interfaces.Storage, error) {
	stg := FileStorage{
		path: p,
	}
	err := stg.Init()
	if err != nil {
		return nil, err
	}
	do.ProvideNamedValue[interfaces.Storage](nil, interfaces.DoStorage, &stg)
	return &stg, nil
}

// Init initialize the file based storage
func (f *FileStorage) Init() error {
	if _, err := os.Stat(f.path); err != nil {
		err := os.MkdirAll(f.path, os.ModePerm)
		if err != nil {
			return err
		}
	}
	b, err := badger.Open(badger.DefaultOptions(f.path).WithIndexCacheSize(100 << 20).WithSyncWrites(true))
	if err != nil {
		return err
	}
	f.db = b
	return nil
}

// Close closes the database, freeing all needed resources
func (f *FileStorage) Close() error {
	f.db.Close()
	do.ShutdownNamed(nil, interfaces.DoStorage)
	return nil
}

// AddGroup adding a group to internal store
func (f *FileStorage) AddGroup(g model.Group) (string, error) {
	err := f.update(groupKey, g.Name, g)
	if err != nil {
		return "", err
	}
	return g.Name, nil
}

// HasGroup checks if a group is present
func (f *FileStorage) HasGroup(n string) (found bool) {
	return f.has(groupKey, n)
}

// DeleteGroup deletes a group if present
func (f *FileStorage) DeleteGroup(n string) (bool, error) {
	err := f.delete(groupKey, n)
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetGroups getting a list of all groups defined
func (f *FileStorage) GetGroups() ([]model.Group, error) {
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
func (f *FileStorage) GetGroup(n string) (*model.Group, bool) {
	var g model.Group
	ok := f.get(groupKey, n, &g)
	if !ok {
		return nil, false
	}
	return &g, true
}

// HasClient checks if a client is present
func (f *FileStorage) HasClient(n string) bool {
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
func (f *FileStorage) AddClient(c model.Client) (string, error) {
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
func (f *FileStorage) UpdateClient(c model.Client) error {
	err := f.update(clientKey, c.AccessKey, c)
	if err != nil {
		return err
	}
	return nil
}

// DeleteClient delete a client
func (f *FileStorage) DeleteClient(a string) (bool, error) {
	err := f.delete(clientKey, a)
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListClients list all clients via callback function
func (f *FileStorage) ListClients(c func(g model.Client) bool) error {
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
func (f *FileStorage) GetClient(a string) (*model.Client, bool) {
	var cl model.Client
	ok := f.get(clientKey, a, &cl)
	if !ok {
		return nil, false
	}
	return &cl, true
}

// ClientByKID returning a client by it's kid of the private key
func (f *FileStorage) ClientByKID(k string) (*model.Client, bool) {
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
func (f *FileStorage) AccessKey(n string) (string, bool) {
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
func (f *FileStorage) StoreEncryptKey(e model.EncryptKey) error {
	err := f.update(encryptionKey, e.ID, e)
	if err != nil {
		return err
	}
	return nil
}

// GetEncryptKey stores the encrypt keys
func (f *FileStorage) GetEncryptKey(id string) (*model.EncryptKey, bool) {
	var e model.EncryptKey
	ok := f.get(encryptionKey, id, &e)
	if !ok {
		return nil, false
	}
	return &e, true
}

// ListEncryptKeys list all clients via callback function
func (f *FileStorage) ListEncryptKeys(s, l int64, c func(c model.EncryptKey) bool) error {
	var cnt int64
	cnt = 0
	err := f.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(encryptionKey)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			cnt++
			if cnt > s && cnt < (s+l) {
				item := it.Item()
				var g model.EncryptKey
				valCopy, err := item.ValueCopy(nil)
				err = json.Unmarshal(valCopy, &g)
				if err != nil {
					return err
				}
				if !c(g) {
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (f *FileStorage) update(t, k string, p any) error {
	v, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return f.db.Update(func(txn *badger.Txn) error {
		err := txn.Set(buildKey(t, k), v)
		return err
	})
}

func (f *FileStorage) has(t, k string) (found bool) {
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

func (f *FileStorage) get(t, k string, v any) bool {
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

func (f *FileStorage) delete(t, k string) error {
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

func (f *FileStorage) clear() error {
	return f.db.DropAll()
}

func buildKey(t, k string) []byte {
	return []byte(fmt.Sprintf("%s_%s", t, k))
}
