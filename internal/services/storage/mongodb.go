// Package mongodb using a mongo db as a index engine for the search
package storage

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/rs/xid"
	"github.com/samber/do"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/serror"
	"github.com/willie68/micro-vault/internal/services/keyman"
	cry "github.com/willie68/micro-vault/pkg/crypt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	driver "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// checking interface compatibility
var _ interfaces.Storage = &MongoStorage{}

const (
	smpErrLog = "error: %v"
)

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
	cryptkey []byte
	revokes  sync.Map
}

type bobject struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	Class      string             `bson:"class,omitempty"`
	Identifier string             `bson:"identifier,omitempty"`
	CID        string             `bson:"cid,omitempty"`
	Object     string             `bson:"object,omitempty"`
	Expires    *time.Time         `bson:"expires,omitempty"`
}

type tkrevoke struct {
	ID      string    `json:"id" bson:"identifier"`
	Expires time.Time `json:"expires" bson:"expires"`
}

const (
	colObjects = "objects"
	colBlue    = "_blue"
	colGreen   = "_green"
	cCTkRevoke = "tkrevoke"
	cCGroup    = "group"
	cCClient   = "client"
	cCClientA  = "clientA"
	cCClientK  = "clientK"
	cCCrypt    = "crypt"
	cCData     = "data"

	cCMasterCrypt     = "master"
	cMasterKeyMessage = "micro-vault-master-key"
)

// NewMongoStorage initialize the mongo db for usage in this service
func NewMongoStorage(mcnfg MongoDBConfig) (interfaces.Storage, error) {
	if len(mcnfg.Hosts) == 0 {
		return nil, errors.New("no mongo hosts found. check config")
	}
	stg, err := prepareMongoClient(mcnfg)
	if err != nil {
		logger.Errorf("%v", err)
		return nil, err
	}

	do.ProvideValue[interfaces.Storage](nil, stg)
	err = stg.Init()
	if err != nil {
		logger.Errorf("%v", err)
		return nil, err
	}
	return stg, nil
}

func prepareMongoClient(mcnfg MongoDBConfig) (*MongoStorage, error) {
	rb := bson.NewRegistry()
	rb.RegisterTypeMapEntry(bson.TypeEmbeddedDocument, reflect.TypeOf(bson.M{}))

	uri := fmt.Sprintf("mongodb://%s", mcnfg.Hosts[0])
	opts := options.Client().SetRegistry(rb)
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
		logger.Errorf("%v", err)
		return nil, err
	}

	database := client.Database(mcnfg.Database)

	stg := MongoStorage{
		mcnfg:    mcnfg,
		client:   client,
		database: database,
		ctx:      ctx,
		knm:      do.MustInvoke[keyman.Keyman](nil),
	}
	return &stg, nil
}

// Init initialize the connection to the mongo db. cerate collections with index as needed
func (m *MongoStorage) Init() error {
	err := m.initCollection(colBlue)
	if err != nil {
		err = m.initCollection(colGreen)
	}
	if err != nil {
		return err
	}
	return nil
}

func (m *MongoStorage) initCollection(n string) error {
	colName := colObjects + n
	m.colObj = m.database.Collection(colName)
	ok, err := checkForIndex(m.colObj)
	if err != nil {
		return err
	}
	if !ok {
		logger.Alert("There is no additional index on mongo collection \"objects\". \r\nPlease consider to add an extra index. See readme for explanation.")
	}
	_, err = m.ensureTTLIndex(m.colObj)
	if err != nil {
		return err
	}
	err = m.ensureEncryption()
	if err != nil {
		return err
	}
	m.revokes = sync.Map{}
	return nil
}

func (m *MongoStorage) ensureTTLIndex(c *driver.Collection) (bool, error) {
	idx := c.Indexes()
	index := driver.IndexModel{
		Keys:    bson.D{{Key: "expires", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(60).SetName("expires"),
	}

	_, err := idx.CreateOne(m.ctx, index)
	if err != nil {
		return false, err
	}
	return true, nil
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

func (m *MongoStorage) ensureEncryption() error {
	opts := options.FindOne()
	flt := bson.D{
		{Key: "class", Value: cCCrypt},
		{Key: "identifier", Value: cCMasterCrypt},
		{Key: "cid", Value: m.knm.KID()},
	}

	res := m.colObj.FindOne(m.ctx, flt, opts)
	if res == nil || res.Err() == driver.ErrNoDocuments {
		return m.newEncryption()
	}
	if res.Err() != nil {
		return res.Err()
	}
	var result bson.M
	err := res.Decode(&result)
	if err != nil {
		return err
	}
	// Testing if database can be used with the service key pair
	err = m.ensureDatabase(result)
	if err != nil {
		return err
	}
	sobj, ok := result["object"].(string)
	if ok {
		obj, err := cry.DecryptKey(*m.knm.PrivateKey(), sobj)
		if err != nil {
			return err
		}
		var e model.EncryptKey
		err = json.Unmarshal([]byte(obj), &e)
		if err != nil {
			return err
		}
		m.cryptkey, err = hex.DecodeString(e.Key)
		if err != nil {
			return err
		}
		return nil
	}
	return serror.ErrUnknowError
}

func (m *MongoStorage) ensureDatabase(mp primitive.M) error {
	mk, ok := mp["message"].(string)
	if ok {
		msg, err := cry.DecryptKey(*m.knm.PrivateKey(), mk)
		if err != nil {
			return err
		}
		if msg != cMasterKeyMessage {
			return errors.New("can't use mongo database. Different encryption key")
		}
	}
	return nil
}

func (m *MongoStorage) newEncryption() error {
	id := xid.New().String()
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		return err
	}
	_, err = aes.NewCipher(buf)
	if err != nil {
		return err
	}

	e := model.EncryptKey{
		ID:      id,
		Alg:     "AES-256",
		Key:     hex.EncodeToString(buf),
		Created: time.Now(),
		Group:   "system",
	}

	mk, err := cry.EncryptKey(m.knm.PublicKey(), cMasterKeyMessage)
	if err != nil {
		return err
	}

	js, err := json.Marshal(e)
	if err != nil {
		return err
	}
	ct, err := cry.EncryptKey(m.knm.PublicKey(), string(js))
	if err != nil {
		return err
	}

	opts := options.FindOneAndReplace().SetUpsert(true)
	flt := bson.D{
		{Key: "class", Value: cCCrypt},
		{Key: "identifier", Value: cCMasterCrypt},
		{Key: "cid", Value: m.knm.KID()},
	}

	obj := bson.D{
		{Key: "class", Value: cCCrypt},
		{Key: "identifier", Value: cCMasterCrypt},
		{Key: "cid", Value: m.knm.KID()},
		{Key: "object", Value: ct},
		{Key: "message", Value: mk},
	}

	res := m.colObj.FindOneAndReplace(m.ctx, flt, obj, opts)
	if res.Err() != nil {
		if res.Err() != driver.ErrNoDocuments {
			return res.Err()
		}
	}
	m.cryptkey = buf
	return nil
}

// Close closing the connection to mongo
func (m *MongoStorage) Close() error {
	err := m.client.Disconnect(m.ctx)
	return err
}

// RevokeToken set this token id to the revoked token
func (m *MongoStorage) RevokeToken(id string, exp time.Time) error {
	if time.Now().After(exp) {
		return nil
	}
	et := tkrevoke{
		ID:      id,
		Expires: exp,
	}
	err := m.upsert(cCTkRevoke, id, &exp, et)
	if err != nil {
		return err
	}
	return nil
}

// IsRevoked checking if an token id is already revoked
func (m *MongoStorage) IsRevoked(id string) bool {
	found, err := m.exists(cCTkRevoke, id)
	if err != nil {
		return false
	}
	return found
}

// AddGroup adding a group to internal store
func (m *MongoStorage) AddGroup(g model.Group) (string, error) {
	err := m.upsert(cCGroup, g.Name, nil, g)
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
		{Key: "class", Value: cCGroup},
	}
	cur, err := m.colObj.Find(m.ctx, obj, opts)
	if err != nil {
		return []model.Group{}, err
	}
	defer cur.Close(m.ctx)

	gl := make([]model.Group, 0)

	for cur.Next(m.ctx) {
		var result bson.M
		err := cur.Decode(&result)
		if err != nil {
			logger.Errorf(smpErrLog, err)
		}
		var g model.Group
		res, ok := result["object"].(string)
		if ok {
			err = m.decrypt(res, &g)
			if err != nil {
				logger.Errorf(smpErrLog, err)
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
		logger.Errorf(smpErrLog, err)
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
		logger.Errorf("has client: %v", err)
		return false
	}
	if !found {
		found, err = m.exists(cCClientA, n)
		if err != nil {
			logger.Errorf("has client: %v", err)
			return false
		}
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
	err = m.upsert(cCClient, c.Name, nil, c)
	if err != nil {
		return "", err
	}
	err = m.upsert(cCClientA, c.AccessKey, nil, c)
	if err != nil {
		return "", err
	}
	if c.KID != "" {
		err = m.upsert(cCClientK, c.KID, nil, c)
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
		{Key: "class", Value: cCClient},
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
			err = m.decrypt(res, &g)
			if err != nil {
				return err
			}
			ok := c(g)
			if !ok {
				break
			}
		}
	}
	return cur.Err()
}

// GetClient returning a client with an access key
func (m *MongoStorage) GetClient(a string) (*model.Client, bool) {
	var c model.Client
	ok, err := m.one(cCClientA, a, &c)
	if err != nil {
		logger.Errorf(smpErrLog, err)
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
		logger.Errorf(smpErrLog, err)
		return "", false
	}
	if !ok {
		return "", false
	}
	return c.AccessKey, true
}

// StoreEncryptKey stores the encrypt keys
func (m *MongoStorage) StoreEncryptKey(e model.EncryptKey) error {
	if e.ID == "" {
		return serror.ErrMissingID
	}
	err := m.upsert(cCCrypt, e.ID, nil, e)
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

// HasEncryptKey checks if a key is present
func (m *MongoStorage) HasEncryptKey(id string) bool {
	var e model.EncryptKey
	ok, err := m.one(cCCrypt, id, &e)
	if err != nil || !ok {
		return false
	}
	return true
}

// ListEncryptKeys list all clients via callback function
func (m *MongoStorage) ListEncryptKeys(s, l int64, c func(c model.EncryptKey) bool) error {
	opts := options.Find().SetSort(bson.D{{Key: "identifier", Value: 1}}).SetSkip(s).SetLimit(l)
	obj := bson.D{
		{Key: "class", Value: cCCrypt},
		{Key: "identifier", Value: bson.D{{Key: "$ne", Value: cCMasterCrypt}}},
	}
	cur, err := m.colObj.Find(m.ctx, obj, opts)
	if err != nil {
		return err
	}
	defer cur.Close(m.ctx)

	for cur.Next(m.ctx) {
		var result bson.M
		err := cur.Decode(&result)
		if err != nil {
			logger.Errorf("lkeys:"+smpErrLog, err)
			continue
		}
		var g model.EncryptKey
		res, ok := result["object"].(string)
		if ok {
			err = m.decrypt(res, &g)
			if err != nil {
				logger.Errorf("lkeys:"+smpErrLog, err)
				continue
			}
			ok := c(g)
			if !ok {
				break
			}
		}
	}
	return cur.Err()
}

// DeleteEncryptKey deletes the encrytion key
func (m *MongoStorage) DeleteEncryptKey(id string) (bool, error) {
	ok, err := m.delete(cCCrypt, id)
	if err != nil || !ok {
		return false, err
	}
	return true, nil
}

// StoreData stores the data
func (m *MongoStorage) StoreData(data model.Data) error {
	if data.ID == "" {
		return serror.ErrMissingID
	}
	err := m.upsert(cCData, data.ID, nil, data)
	if err != nil {
		return err
	}
	return nil
}

// GetData retrieving the data model
func (m *MongoStorage) GetData(id string) (*model.Data, bool) {
	var d model.Data
	ok, err := m.one(cCData, id, &d)
	if err != nil || !ok {
		return nil, false
	}
	return &d, true
}

// DeleteData removes the data model from storage
func (m *MongoStorage) DeleteData(id string) (bool, error) {
	ok, err := m.delete(cCData, id)
	if err != nil || !ok {
		return false, err
	}
	return true, nil
}

// ListData list all data entries via callback function
func (m *MongoStorage) ListData(s, l int64, c func(c model.Data) bool) error {
	opts := options.Find().SetSort(bson.D{{Key: "identifier", Value: 1}}).SetSkip(s).SetLimit(l)
	obj := bson.D{
		{Key: "class", Value: cCData},
		{Key: "identifier", Value: bson.D{{Key: "$ne", Value: cCMasterCrypt}}},
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
			logger.Errorf("lkeys: error: %v", err)
			continue
		}
		var g model.Data
		res, ok := result.Map()["object"].(string)
		if ok {
			err = m.decrypt(res, &g)
			if err != nil {
				logger.Errorf("lkeys: error: %v", err)
				continue
			}
			ok := c(g)
			if !ok {
				break
			}
		}
	}
	return cur.Err()
}

func (m *MongoStorage) clear() error {
	err := m.colObj.Drop(m.ctx)
	if err != nil {
		return err
	}
	return nil
}

func (m *MongoStorage) upsert(c, i string, exp *time.Time, o any) error {
	so, err := m.encrypt(o)
	if err != nil {
		return err
	}

	obj := bobject{
		Class:      c,
		Identifier: i,
		Object:     so,
	}
	if exp != nil {
		obj.Expires = exp
	}

	opts := options.FindOneAndReplace().SetUpsert(true)
	flt := bson.D{
		{Key: "class", Value: c},
		{Key: "identifier", Value: i},
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
		{Key: "class", Value: c},
		{Key: "identifier", Value: i},
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
	return false, serror.ErrUnknowError
}

func (m *MongoStorage) one(c, i string, obj any) (bool, error) {
	opts := options.FindOne()
	flt := bson.D{
		{Key: "class", Value: c},
		{Key: "identifier", Value: i},
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
			err = m.decrypt(res, &obj)
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
		{Key: "class", Value: c},
		{Key: "identifier", Value: i},
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

func (m *MongoStorage) decrypt(j string, o any) error {
	ds, err := cry.Decrypt(m.cryptkey, j)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(ds), &o)
}

func (m *MongoStorage) encrypt(o any) (string, error) {
	js, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	cs, err := cry.Encrypt(m.cryptkey, string(js))
	if err != nil {
		return "", err
	}
	return cs, nil
}
