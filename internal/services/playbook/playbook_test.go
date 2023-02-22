package playbook

import (
	"testing"

	"github.com/willie68/micro-vault/internal/services/storage"

	"github.com/stretchr/testify/assert"
)

func TestPlaybook(t *testing.T) {
	ast := assert.New(t)
	stg, err := storage.NewMemory()
	ast.Nil(err)
	ast.NotNil(stg)

	pb := NewPlaybook("../../../testdata/playbook.json", stg)
	ast.NotNil(pb)

	err = pb.Play()
	ast.Nil(err)

	ok := stg.HasGroup("group1")
	ast.True(ok)
	ok = stg.HasClient("tester1")
	ast.True(ok)
}

func TestPlaybookMissingFile(t *testing.T) {
	ast := assert.New(t)
	stg, err := storage.NewMemory()
	ast.Nil(err)
	ast.NotNil(stg)

	pb := NewPlaybook("../../../testdata/playbook1.json", stg)
	ast.NotNil(pb)
	err = pb.Play()
	ast.NotNil(err)

	pb = NewPlaybook("../../../testdata/playbook.yaml", stg)
	ast.NotNil(pb)
	err = pb.Play()
	ast.NotNil(err)
}
