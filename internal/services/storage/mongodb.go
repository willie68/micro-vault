// Package mongodb using a mongo db as a index engine for the search
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/interfaces"
	log "github.com/willie68/micro-vault/internal/logging"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services"
	"github.com/willie68/micro-vault/internal/services/keyman"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
	colObj   *driver.Collection
}

type bobject struct {
	ID         primitive.ObjectID `bson:"_id"`
	Class      string             `bson:"class"`
	Identifier string             `bson:"identifier"`
	Object     string             `bson:"object"`
}

const (
	colObjects = "objects"
	cCGroup    = "group"
	cCClient   = "client"
)

// NewMongoStorage initialize the mongo db for usage in this service
func NewMongoStorage(mcnfg MongoDBConfig) (interfaces.Storage, error) {
	if len(mcnfg.Hosts) == 0 {
		return nil, errors.New("no mongo hosts found. check config")
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
		return nil, err
	}

	database := client.Database(mcnfg.Database)

	stg := MongoStorage{
		mcnfg:    mcnfg,
		client:   client,
		database: database,
		ctx:      ctx,
		knm:      do.MustInvokeNamed[keyman.Keyman](nil, keyman.DoKeyman),
	}
	do.ProvideNamedValue[interfaces.Storage](nil, interfaces.DoStorage, &stg)
	err = stg.Init()
	if err != nil {
		log.Logger.Errorf("%v", err)
		return nil, err
	}
	return &stg, nil
}

// Init initialize the connection to the mongo db. cerate collections with index as needed
func (m *MongoStorage) Init() error {
	m.colObj = m.database.Collection(colObjects)
	ok, err := checkForIndex(m.colObj)
	if err != nil {
		return err
	}
	if !ok {
		log.Logger.Alert("There is no additional index on mongo collection \"objects\". \r\nPlease consider to add an extra index. See readme for explanation.")
	}
	return nil
}

func checkForIndex(c *driver.Collection) (bool, error) {
	idx := c.Indexes()
	opts := options.ListIndexes().SetMaxTime(2 * time.Second)
	cursor, err := idx.List(context.TODO(), opts)
	if err != nil {
		return false, err
	}
	var result []bson.M
	if err = cursor.All(context.TODO(), &result); err != nil {
		return false, err
	}
	return len(result) > 1, nil
}

// Close closing the connection to mongo
func (m *MongoStorage) Close() error {
	m.client.Disconnect(m.ctx)
	return nil
}

// AddGroup adding a group to internal store
func (m *MongoStorage) AddGroup(g model.Group) (string, error) {
	err := m.upsert(cCGroup, g.Name, g)
	if err != nil {
		return "", err
	}
	return g.Name, nil
}

// HasGroup checks if a group is present
func (m *MongoStorage) HasGroup(n string) (found bool) {
	found, err := m.exists(cCGroup, n)
	if err != nil {
		return false
	}
	return found
}

// DeleteGroup deletes a group if present
func (m *MongoStorage) DeleteGroup(n string) (bool, error) {
	ok, err := m.delete(cCGroup, n)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// GetGroups getting a list of all groups defined
func (m *MongoStorage) GetGroups() ([]model.Group, error) {
	opts := options.Find()
	obj := bson.D{
		{"class", cCGroup},
	}
	cur, err := m.colObj.Find(m.ctx, obj, opts)
	if err != nil {
		return []model.Group{}, err
	}
	defer cur.Close(m.ctx)

	gl := make([]model.Group, 0)

	for cur.Next(m.ctx) {
		var result bson.D
		err := cur.Decode(&result)
		if err != nil {
			log.Logger.Errorf("error: %v", err)
		}
		var g model.Group
		res, ok := result.Map()["object"].(string)
		if ok {
			err = json.Unmarshal([]byte(res), &g)
			if err != nil {
				log.Logger.Errorf("error: %v", err)
			} else {
				gl = append(gl, g)
			}
		}
	}
	if err := cur.Err(); err != nil {
		return []model.Group{}, err
	}
	return gl, nil
}

// GetGroup getting a single group
func (m *MongoStorage) GetGroup(n string) (*model.Group, bool) {
	var g model.Group
	ok, err := m.one(cCGroup, n, &g)
	if err != nil {
		log.Logger.Errorf("error: %v", err)
		return nil, false
	}
	return &g, ok
}

// HasClient checks if a client is present
func (m *MongoStorage) HasClient(n string) bool {
	found, err := m.exists(cCClient, n)
	if err != nil {
		return false
	}
	return found
}

// AddClient adding the client to the internal storage
func (m *MongoStorage) AddClient(c model.Client) (string, error) {
	err := m.upsert(cCClient, c.Name, c)
	if err != nil {
		return "", err
	}
	err = m.upsert(cCClient, c.AccessKey, c)
	if err != nil {
		return "", err
	}
	return c.Name, nil
}

// UpdateClient adding the client to the internal storage
func (m *MongoStorage) UpdateClient(c model.Client) error {
	return services.ErrNotImplementedYet
}

// DeleteClient delete a client
func (m *MongoStorage) DeleteClient(a string) (bool, error) {
	return false, services.ErrNotImplementedYet
}

// ListClients list all clients via callback function
func (m *MongoStorage) ListClients(c func(g model.Client) bool) error {
	return services.ErrNotImplementedYet
}

// GetClient returning a client with an access key
func (m *MongoStorage) GetClient(a string) (*model.Client, bool) {
	return nil, false
}

// ClientByKID returning a client by it's kid of the private key
func (m *MongoStorage) ClientByKID(k string) (*model.Client, bool) {
	return nil, false
}

// AccessKey returning the access key of client with name
func (m *MongoStorage) AccessKey(n string) (string, bool) {
	return "", false
}

// StoreEncryptKey stores the encrypt keys
func (m *MongoStorage) StoreEncryptKey(e model.EncryptKey) error {
	return services.ErrNotImplementedYet
}

// GetEncryptKey stores the encrypt keys
func (m *MongoStorage) GetEncryptKey(id string) (*model.EncryptKey, bool) {
	return nil, false
}

func (m *MongoStorage) clear() error {
	err := m.colObj.Drop(m.ctx)
	if err != nil {
		return err
	}
	return nil
}

func (m *MongoStorage) upsert(c, i string, o any) error {
	js, err := json.Marshal(o)
	if err != nil {
		return err
	}
	obj := bson.D{
		{"class", c},
		{"identifier", i},
		{"object", string(js)},
	}
	opts := options.FindOneAndReplace().SetUpsert(true)
	flt := bson.D{
		{"class", c},
		{"identifier", i},
	}
	res := m.colObj.FindOneAndReplace(m.ctx, flt, obj, opts)
	if res.Err() != nil {
		if res.Err() == driver.ErrNoDocuments {
			return nil
		}
		return res.Err()
	}
	return nil
}

func (m *MongoStorage) exists(c, i string) (bool, error) {
	opts := options.FindOne()
	obj := bson.D{
		{"class", c},
		{"identifier", i},
	}
	res := m.colObj.FindOne(m.ctx, obj, opts)
	if res != nil {
		if res.Err() == driver.ErrNoDocuments {
			return false, nil
		}
		if res.Err() != nil {
			return false, res.Err()
		}
		return true, nil
	}
	return false, services.ErrUnknowError
}

func (m *MongoStorage) one(c, i string, obj any) (bool, error) {
	opts := options.FindOne()
	flt := bson.D{
		{"class", c},
		{"identifier", i},
	}
	res := m.colObj.FindOne(m.ctx, flt, opts)
	if res != nil {
		if res.Err() == driver.ErrNoDocuments {
			return false, nil
		}
		if res.Err() != nil {
			return false, res.Err()
		}
		var result bson.D
		err := res.Decode(&result)
		if err != nil {
			return false, err
		}
		res, ok := result.Map()["object"].(string)
		if ok {
			err = json.Unmarshal([]byte(res), &obj)
			if err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

func (m *MongoStorage) delete(c, i string) (bool, error) {
	opts := options.Delete()
	flt := bson.D{
		{"class", c},
		{"identifier", i},
	}
	res, err := m.colObj.DeleteOne(m.ctx, flt, opts)
	if err != nil {
		return false, err
	}
	if res != nil {
		return res.DeletedCount == 1, nil
	}
	return false, nil
}
