// Package mongodb using a mongo db as a index engine for the search
package storage

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
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
	colCl    *driver.Collection
	colGr    *driver.Collection
}

type bclient struct {
	ID        primitive.ObjectID `bson:"_id"`
	Name      string             `json:"name" bson:"name"`
	AccessKey string             `json:"accesskey" bson:"accesskey"`
	Secret    string             `json:"secret" bson:"secret"`
	Groups    []string           `json:"groups" bson:"groups"`
	Key       string             `json:"key" bson:"key"`
	KID       string             `json:"kid" bson:"kid"`
}

type bgroup struct {
	ID    primitive.ObjectID `bson:"_id"`
	Name  string             `json:"name" bson:"name"`
	Label map[string]string  `json:"label" bson:"label"`
}

const (
	colClients = "clients"
	colGroups  = "groups"
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
	err := m.initColClients()
	if err != nil {
		return err
	}
	err = m.initColGroups()
	if err != nil {
		return err
	}
	m.colCl = m.database.Collection(colClients)
	m.colGr = m.database.Collection(colGroups)
	return nil
}

func (m *MongoStorage) initColClients() error {
	col := m.database.Collection(colClients)
	// check for indexes
	ok, err := hasIndex(col, "name")
	if err != nil {
		return err
	}
	if !ok {
		log.Logger.Info("colcl: index name found, creating one")
		mod := driver.IndexModel{
			Keys: bson.M{
				"name": 1, // index in ascending order
			},
			Options: options.Index().SetUnique(true).SetName("name"),
		}
		// Create an Index using the CreateOne() method
		_, err := col.Indexes().CreateOne(m.ctx, mod)
		if err != nil {
			return err
		}
	}
	ok, err = hasIndex(col, "accesskey")
	if err != nil {
		return err
	}
	if !ok {
		log.Logger.Info("colcl: index name found, creating one")
		mod := driver.IndexModel{
			Keys: bson.M{
				"accesskey": 1, // index in ascending order
			},
			Options: options.Index().SetUnique(true).SetName("accesskey"),
		}
		// Create an Index using the CreateOne() method
		_, err := col.Indexes().CreateOne(m.ctx, mod)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *MongoStorage) initColGroups() error {
	col := m.database.Collection(colGroups)
	// check for indexes
	ok, err := hasIndex(col, "name")
	if err != nil {
		return err
	}
	if !ok {
		log.Logger.Info("colcl: index name found, creating one")
		mod := driver.IndexModel{
			Keys: bson.M{
				"name": 1, // index in ascending order
			},
			Options: options.Index().SetUnique(true).SetName("name"),
		}
		// Create an Index using the CreateOne() method
		_, err := col.Indexes().CreateOne(m.ctx, mod)
		if err != nil {
			return err
		}
	}
	return nil
}

func hasIndex(c *driver.Collection, n string) (bool, error) {
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
	found := false
	for _, i := range result {
		if strings.EqualFold(i["name"].(string), n) {
			found = true
		}
	}
	return found, nil
}

// Close closing the connection to mongo
func (m *MongoStorage) Close() error {
	m.client.Disconnect(m.ctx)
	return nil
}

// AddGroup adding a group to internal store
func (m *MongoStorage) AddGroup(g model.Group) (string, error) {
	if !m.HasGroup(g.Name) {
		gr := bgroup{
			Name:  g.Name,
			Label: g.Label,
		}
		_, err := m.colGr.InsertOne(m.ctx, gr)
		if err != nil {
			return "", err
		}
		return g.Name, nil
	}
	return "", services.ErrAlreadyExists
}

// HasGroup checks if a group is present
func (m *MongoStorage) HasGroup(n string) (found bool) {
	return false
}

// DeleteGroup deletes a group if present
func (m *MongoStorage) DeleteGroup(n string) (bool, error) {
	return false, services.ErrNotImplementedYet
}

// GetGroups getting a list of all groups defined
func (m *MongoStorage) GetGroups() ([]model.Group, error) {
	return nil, services.ErrNotImplementedYet

}

// GetGroup getting a single group
func (m *MongoStorage) GetGroup(n string) (*model.Group, bool) {
	return nil, false
}

// HasClient checks if a client is present
func (m *MongoStorage) HasClient(n string) bool {
	return false
}

// AddClient adding the client to the internal storage
func (m *MongoStorage) AddClient(c model.Client) (string, error) {
	return "", services.ErrNotImplementedYet
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
	cols, err := m.database.ListCollectionNames(m.ctx, nil, options.ListCollections().SetNameOnly(true))
	if err != nil {
		return err
	}
	for _, col := range cols {
		dc := m.database.Collection(col)
		err := dc.Drop(m.ctx)
		if err != nil {
			log.Logger.Errorf("drop collection error: %v", err)
		}
	}
	return nil
}
