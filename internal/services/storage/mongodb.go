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
	cCClientA  = "clientA"
	cCClientK  = "clientK"
	cCCrypt    = "crypt"
)

// NewMongoStorage initialize the mongo db for usage in this service
func NewMongoStorage(mcnfg MongoDBConfig) (interfaces.Storage, error) {
	if len(mcnfg.Hosts) == 0 {
		return nil, errors.New("no mongo hosts found. check config")
	}
	stg, err := prepareMongoClient(mcnfg)
	if err != nil {
		log.Logger.Errorf("%v", err)
		return nil, err
	}

	do.ProvideNamedValue[interfaces.Storage](nil, interfaces.DoStorage, stg)
	err = stg.Init()
	if err != nil {
		log.Logger.Errorf("%v", err)
		return nil, err
	}
	return stg, nil
}

func prepareMongoClient(mcnfg MongoDBConfig) (*MongoStorage, error) {
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
	if !ok {
		return nil, ok
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
	if m.HasClient(c.Name) {
		return "", errors.New("client already exists")
	}
	ok, err := m.exists(cCClientA, c.AccessKey)
	if err != nil {
		return "", err
	}
	if ok {
		return "", errors.New("client already exists")
	}
	err = m.upsert(cCClient, c.Name, c)
	if err != nil {
		return "", err
	}
	err = m.upsert(cCClientA, c.AccessKey, c)
	if err != nil {
		return "", err
	}
	if c.KID != "" {
		err = m.upsert(cCClientK, c.KID, c)
		if err != nil {
			return "", err
		}
	}
	return c.Name, nil
}

// UpdateClient adding the client to the internal storage
func (m *MongoStorage) UpdateClient(c model.Client) error {
	var cl model.Client
	ok, err := m.one(cCClient, c.Name, &cl)
	if err != nil {
		return err
	}

	if ok {
		_, err = m.delete(cCClient, cl.Name)
		if err != nil {
			return err
		}
		_, err = m.delete(cCClientA, cl.AccessKey)
		if err != nil {
			return err
		}
		_, err = m.delete(cCClientK, cl.KID)
		if err != nil {
			return err
		}
	}

	_, err = m.AddClient(c)
	if err != nil {
		return err
	}
	return nil
}

// DeleteClient delete a client
func (m *MongoStorage) DeleteClient(a string) (bool, error) {
	cl, ok := m.GetClient(a)
	if !ok {
		return false, nil
	}
	ok, err := m.delete(cCClient, cl.Name)
	if err != nil {
		return false, err
	}
	ok2, err := m.delete(cCClientA, cl.AccessKey)
	if err != nil {
		return false, err
	}
	_, err = m.delete(cCClientK, cl.KID)
	if err != nil {
		return false, err
	}
	return ok && ok2, nil
}

// ListClients list all clients via callback function
func (m *MongoStorage) ListClients(c func(g model.Client) bool) error {
	opts := options.Find()
	obj := bson.D{
		{"class", cCClient},
	}
	cur, err := m.colObj.Find(m.ctx, obj, opts)
	if err != nil {
		return err
	}
	defer cur.Close(m.ctx)

	for cur.Next(m.ctx) {
		var result bson.D
		err := cur.Decode(&result)
		if err != nil {
			return err
		}
		var g model.Client
		res, ok := result.Map()["object"].(string)
		if ok {
			err = json.Unmarshal([]byte(res), &g)
			if err != nil {
				return err
			}
			ok := c(g)
			if !ok {
				break
			}
		}
	}
	if err := cur.Err(); err != nil {
		return err
	}
	return nil
}

// GetClient returning a client with an access key
func (m *MongoStorage) GetClient(a string) (*model.Client, bool) {
	var c model.Client
	ok, err := m.one(cCClientA, a, &c)
	if err != nil {
		log.Logger.Errorf("error: %v", err)
		return nil, false
	}
	if !ok {
		return nil, ok
	}
	return &c, ok
}

// ClientByKID returning a client by it's kid of the private key
func (m *MongoStorage) ClientByKID(k string) (*model.Client, bool) {
	var cl model.Client
	ok, err := m.one(cCClientK, k, &cl)
	if err != nil {
		return nil, false
	}
	if !ok {
		return nil, false
	}
	return &cl, true
}

// AccessKey returning the access key of client with name
func (m *MongoStorage) AccessKey(n string) (string, bool) {
	var c model.Client
	ok, err := m.one(cCClient, n, &c)
	if err != nil {
		log.Logger.Errorf("error: %v", err)
		return "", false
	}
	if !ok {
		return "", false
	}
	return c.AccessKey, true
}

// StoreEncryptKey stores the encrypt keys
func (m *MongoStorage) StoreEncryptKey(e model.EncryptKey) error {
	err := m.upsert(cCCrypt, e.ID, e)
	if err != nil {
		return err
	}
	return nil
}

// GetEncryptKey stores the encrypt keys
func (m *MongoStorage) GetEncryptKey(id string) (*model.EncryptKey, bool) {
	var e model.EncryptKey
	ok, err := m.one(cCCrypt, id, &e)
	if err != nil || !ok {
		return nil, false
	}
	return &e, true
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
