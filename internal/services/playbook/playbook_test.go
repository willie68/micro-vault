package playbook

import (
	"testing"

	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services/storage"

	"github.com/stretchr/testify/assert"
)

var stg interfaces.Storage

func init() {
	var err error
	stg, err = storage.NewFileStorage()
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

	ok := stg.HasGroup("group1")
	ast.True(ok)
	ok = stg.HasClient("tester1")
	ast.True(ok)
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

	err := pb.Play()
	ast.Nil(err)

	ast.True(stg.HasGroup("group1"))

	ast.True(stg.HasClient("tester1"))

	ast.True(stg.HasClient("tester2"))

	ast.False(stg.HasClient("tester3"))
}
