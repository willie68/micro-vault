package playbook

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/xid"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services/storage"

	"github.com/stretchr/testify/assert"
	cry "github.com/willie68/micro-vault/pkg/crypt"
)

var stg interfaces.Storage

func init() {
	var err error
	stg, err = storage.NewMemory()
	if err != nil {
		panic(err)
	}
}

func TestPlaybook(t *testing.T) {
	ast := assert.New(t)

	pb := NewPlaybookFile("../../../testdata/playbook.json")
	ast.NotNil(pb)

	err := pb.Load()
	ast.Nil(err)

	err = pb.Play()
	ast.Nil(err)

	ast.True(stg.HasGroup("group1"))
	ast.True(stg.HasClient("tester1"))
	ast.True(stg.HasGroup("tester1"))
	cl, ok := stg.GetClient("12345678")
	ast.True(ok)
	js, err := json.Marshal(cl)
	ast.Nil(err)
	fmt.Println(string(js))
}

func TestPlaybookMissingFile(t *testing.T) {
	ast := assert.New(t)

	pb := NewPlaybookFile("../../../testdata/playbook1.json")
	ast.NotNil(pb)
	err := pb.Load()
	ast.NotNil(err)
	err = pb.Play()
	ast.Nil(err)

	pb = NewPlaybookFile("../../../testdata/playbook.yaml")
	ast.NotNil(pb)
	err = pb.Load()
	ast.NotNil(err)
}

func TestPlaybookModel(t *testing.T) {
	ast := assert.New(t)
	stg.Init()

	pm := model.Playbook{
		Groups: []model.Group{
			model.Group{
				Name: "group1",
			},
			model.Group{
				Name: "group2",
			},
		},
		Clients: []model.Client{
			model.Client{
				Name:      "tester1",
				AccessKey: "123",
			},
			model.Client{
				Name:      "tester2",
				AccessKey: "456",
			},
		},
	}
	pb := NewPlaybook(pm)

	ast.False(stg.HasGroup("group1"))
	ast.False(stg.HasClient("tester1"))
	ast.False(stg.HasGroup("tester1"))

	err := pb.Play()
	ast.Nil(err)

	ast.True(stg.HasGroup("group1"))

	ast.True(stg.HasClient("tester1"))
	ast.True(stg.HasGroup("tester1"))

	ast.True(stg.HasClient("tester2"))
	ast.True(stg.HasGroup("tester2"))

	ast.False(stg.HasClient("tester3"))
}

func TestPlaybookExport(t *testing.T) {
	ast := assert.New(t)
	stg.Init()
	pb := NewPlaybookFile("../../../testdata/playbook.json")
	ast.NotNil(pb)
	err := pb.Load()
	ast.Nil(err)
	err = pb.Play()
	ast.Nil(err)

	e, err := newEncryptKey()
	ast.Nil(err)
	stg.StoreEncryptKey(*e)

	err = pb.Export("../../../testdata/playbook_export.json")
	ast.Nil(err)
}

func TestBigExport(t *testing.T) {
	ast := assert.New(t)
	stg.Init()
	pb := NewPlaybook(model.Playbook{})
	ast.NotNil(pb)

	for x := 0; x < 100; x++ {
		g := model.Group{
			Name: fmt.Sprintf("group_%d", x),
			Label: map[string]string{
				"de": fmt.Sprintf("Gruppe %d", x),
				"en": fmt.Sprintf("Group %d", x),
			},
		}
		_, err := stg.AddGroup(g)
		ast.Nil(err)
	}
	for x := 0; x < 100; x++ {
		c, err := newClient(fmt.Sprintf("client_%d", x), []string{fmt.Sprintf("group_%d", x)})
		ast.Nil(err)
		_, err = stg.AddClient(*c)
		ast.Nil(err)
	}
	for x := 0; x < 10000; x++ {
		e, err := newEncryptKey()
		ast.Nil(err)
		err = stg.StoreEncryptKey(*e)
		ast.Nil(err)
	}

	err := pb.Export("../../../testdata/playbook_export.json")
	ast.Nil(err)

	data, err := os.ReadFile("../../../testdata/playbook_export.json")
	ast.Nil(err)
	var pm model.Playbook
	err = json.Unmarshal(data, &pm)
	ast.Nil(err)
	ast.Equal(100, len(pm.Groups))
	ast.Equal(100, len(pm.Clients))
	ast.Equal(10000, len(pm.Keys))
}

func newEncryptKey() (*model.EncryptKey, error) {
	id := xid.New().String()
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	e := model.EncryptKey{
		ID:      id,
		Alg:     "AES-256",
		Key:     hex.EncodeToString(buf),
		Created: time.Now(),
		Group:   "group1",
	}
	return &e, nil
}

func newClient(n string, g []string) (*model.Client, error) {
	token := make([]byte, 16)
	_, err := rand.Read(token)
	if err != nil {
		return nil, err
	}
	rsk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	pem, err := cry.Prv2Pem(rsk)
	if err != nil {
		return nil, err
	}
	kid, err := cry.GetKID(rsk)
	if err != nil {
		return nil, err
	}
	c := model.Client{
		Name:      n,
		AccessKey: uuid.NewString(),
		Secret:    hex.EncodeToString(token),
		Groups:    g,
		Key:       string(pem),
		KID:       kid,
	}
	return &c, nil
}
