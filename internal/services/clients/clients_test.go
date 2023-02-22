package clients

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/services/playbook"
	"github.com/willie68/micro-vault/internal/services/storage"
)

func TestClientLogin(t *testing.T) {
	ast := assert.New(t)
	stg, err := storage.NewMemory()
	ast.Nil(err)
	ast.NotNil(stg)
	pb := playbook.NewPlaybook("../../../testdata/playbook.json", stg)
	err = pb.Play()
	ast.Nil(err)

	cls, err := NewClients(stg)
	ast.Nil(err)

	tk, err := cls.Login("12345678", "yxcvb")
	ast.Nil(err)
	t.Logf("token: %s", tk)
}
