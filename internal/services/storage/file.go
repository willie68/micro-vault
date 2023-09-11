package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/interfaces"
	log "github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/serror"
)

// FileStorage storage engine on file system
type FileStorage struct {
	path    string
	db      *badger.DB
	revokes sync.Map
	ticker  *time.Ticker
	tckDone chan bool
}

const (
	groupKey      = "group"
	clientKey     = "client"
	nameKey       = "name"
	encryptionKey = "encryption"
	dataKey       = "data"
)

var _ interfaces.Storage = &FileStorage{}

// NewFileStorage creates a new memory storage
func NewFileStorage(path string) (interfaces.Storage, error) {
	stg := FileStorage{
		path: path,
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
	f.revokes = sync.Map{}
	f.tckDone = make(chan bool)
	f.ticker = time.NewTicker(1 * time.Minute)

	go func() {
		for {
			select {
			case <-f.tckDone:
				return
			case <-f.ticker.C:
				f.cleanup()
			}
		}
	}()

	return nil
}

// Close closes the database, freeing all needed resources
func (f *FileStorage) Close() error {
	f.db.Close()
	err := do.ShutdownNamed(nil, interfaces.DoStorage)
	f.ticker.Stop()
	f.tckDone <- true
	return err
}

func (f *FileStorage) cleanup() {
	f.revokes.Range(func(key, value any) bool {
		exp := value.(time.Time)
		if time.Now().After(exp) {
			f.revokes.Delete(key)
		}
		return true
	})
}

// RevokeToken set this token id to the revoked token
func (f *FileStorage) RevokeToken(id string, exp time.Time) error {
	if time.Now().After(exp) {
		return nil
	}
	f.revokes.Store(id, exp)
	return nil
}

// IsRevoked checking if an token id is already revoked
func (f *FileStorage) IsRevoked(id string) bool {
	_, ok := f.revokes.Load(id)
	return ok
}

// AddGroup adding a group to internal store
func (f *FileStorage) AddGroup(group model.Group) (string, error) {
	err := f.update(groupKey, group.Name, group)
	if err != nil {
		return "", err
	}
	return group.Name, nil
}

// HasGroup checks if a group is present
func (f *FileStorage) HasGroup(name string) (found bool) {
	return f.has(groupKey, name)
}

// DeleteGroup deletes a group if present
func (f *FileStorage) DeleteGroup(name string) (bool, error) {
	err := f.delete(groupKey, name)
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
func (f *FileStorage) GetGroup(name string) (*model.Group, bool) {
	var g model.Group
	ok := f.get(groupKey, name, &g)
	if !ok {
		return nil, false
	}
	return &g, true
}

// HasClient checks if a client is present
func (f *FileStorage) HasClient(name string) bool {
	found := false
	err := f.ListClients(func(g model.Client) bool {
		if g.Name == name {
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
func (f *FileStorage) AddClient(client model.Client) (string, error) {
	if f.has(clientKey, client.AccessKey) {
		return "", errors.New("client already exists")
	}
	found := false
	err := f.ListClients(func(g model.Client) bool {
		if g.Name == client.Name {
			found = true
			return false
		}
		return true
	})
	if err != nil {
		return "", err
	}
	if found {
		return "", errors.New("client already exists")
	}
	err = f.update(clientKey, client.AccessKey, client)
	if err != nil {
		return "", err
	}
	return client.Name, nil
}

// UpdateClient adding the client to the internal storage
func (f *FileStorage) UpdateClient(client model.Client) error {
	err := f.update(clientKey, client.AccessKey, client)
	if err != nil {
		return err
	}
	return nil
}

// DeleteClient delete a client
func (f *FileStorage) DeleteClient(access string) (bool, error) {
	err := f.delete(clientKey, access)
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListClients list all clients via callback function
func (f *FileStorage) ListClients(callback func(cl model.Client) bool) error {
	err := f.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(clientKey)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			var g model.Client
			valCopy, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			err = json.Unmarshal(valCopy, &g)
			if err != nil {
				return err
			}
			if !callback(g) {
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
func (f *FileStorage) GetClient(access string) (*model.Client, bool) {
	var cl model.Client
	ok := f.get(clientKey, access, &cl)
	if !ok {
		return nil, false
	}
	return &cl, true
}

// ClientByKID returning a client by it's kid of the private key
func (f *FileStorage) ClientByKID(kid string) (*model.Client, bool) {
	var c *model.Client
	err := f.ListClients(func(g model.Client) bool {
		if g.KID == kid {
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
func (f *FileStorage) AccessKey(name string) (string, bool) {
	key := ""
	found := false
	err := f.ListClients(func(g model.Client) bool {
		if g.Name == name {
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
func (f *FileStorage) StoreEncryptKey(encKey model.EncryptKey) error {
	if encKey.ID == "" {
		return serror.ErrMissingID
	}
	err := f.update(encryptionKey, encKey.ID, encKey)
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

// HasEncryptKey checks if a key is present
func (f *FileStorage) HasEncryptKey(id string) bool {
	return f.has(encryptionKey, id)
}

// ListEncryptKeys list all keys via callback function
func (f *FileStorage) ListEncryptKeys(start, length int64, callback func(c model.EncryptKey) bool) error {
	err := f.db.View(func(txn *badger.Txn) error {
		var cnt int64
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(encryptionKey)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			cnt++
			if cnt > start && cnt < (start+length) {
				item := it.Item()
				var g model.EncryptKey
				valCopy, err := item.ValueCopy(nil)
				if err != nil {
					return err
				}
				err = json.Unmarshal(valCopy, &g)
				if err != nil {
					return err
				}
				if !callback(g) {
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

// DeleteEncryptKey deletes the encrytion key
func (f *FileStorage) DeleteEncryptKey(id string) (bool, error) {
	err := f.delete(encryptionKey, id)
	if err != nil {
		return false, err
	}
	return true, nil
}

// StoreData stores the data
func (f *FileStorage) StoreData(data model.Data) error {
	if data.ID == "" {
		return serror.ErrMissingID
	}
	err := f.update(dataKey, data.ID, data)
	if err != nil {
		return err
	}
	return nil
}

// GetData retrieving the data model
func (f *FileStorage) GetData(id string) (*model.Data, bool) {
	var e model.Data
	ok := f.get(dataKey, id, &e)
	if !ok {
		return nil, false
	}
	return &e, true
}

// DeleteData removes the data model from storage
func (f *FileStorage) DeleteData(id string) (bool, error) {
	if !f.has(dataKey, id) {
		return false, nil
	}
	err := f.delete(dataKey, id)
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListData list all datas via callback function
func (f *FileStorage) ListData(start, length int64, callback func(c model.Data) bool) error {
	err := f.db.View(func(txn *badger.Txn) error {
		var cnt int64
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(dataKey)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			cnt++
			if cnt > start && cnt < (start+length) {
				item := it.Item()
				var g model.Data
				valCopy, err := item.ValueCopy(nil)
				if err != nil {
					return err
				}
				err = json.Unmarshal(valCopy, &g)
				if err != nil {
					return err
				}
				if !callback(g) {
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

func (f *FileStorage) update(tenant, key string, payload any) error {
	v, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return f.db.Update(func(txn *badger.Txn) error {
		err := txn.Set(buildKey(tenant, key), v)
		return err
	})
}

func (f *FileStorage) has(tenant, key string) (found bool) {
	tkey := string(buildKey(tenant, key))
	err := f.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		prefix := []byte(tenant)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			found = string(item.Key()) == tkey
			if found {
				it.Close()
			}
		}
		return nil
	})
	if err != nil {
		log.Logger.Errorf("error checking entry: %v", err)
		return false
	}
	return
}

func (f *FileStorage) get(tenant, key string, value any) bool {
	tkey := buildKey(tenant, key)
	err := f.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(tkey)
		if err != nil {
			return err
		}
		valCopy, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		err = json.Unmarshal(valCopy, value)
		return err
	})
	if err != nil {
		log.Logger.Errorf("error getting entry: %v", err)
		return false
	}
	return true
}

func (f *FileStorage) delete(tenant, key string) error {
	tkey := buildKey(tenant, key)
	err := f.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(tkey)
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

func buildKey(tenant, key string) []byte {
	return []byte(fmt.Sprintf("%s_%s", tenant, key))
}
