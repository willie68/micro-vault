package playbook

import (
	"testing"

	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/services/storage"

	"github.com/stretchr/testify/assert"
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

	pb := NewPlaybook("../../../testdata/playbook.json")
	ast.NotNil(pb)

	err := pb.Play()
	ast.Nil(err)

	ok := stg.HasGroup("group1")
	ast.True(ok)
	ok = stg.HasClient("tester1")
	ast.True(ok)
}

func TestPlaybookMissingFile(t *testing.T) {
	ast := assert.New(t)

	pb := NewPlaybook("../../../testdata/playbook1.json")
	ast.NotNil(pb)
	err := pb.Play()
	ast.NotNil(err)

	pb = NewPlaybook("../../../testdata/playbook.yaml")
	ast.NotNil(pb)
	err = pb.Play()
	ast.NotNil(err)
}
