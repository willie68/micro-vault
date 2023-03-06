package admin

import (
	"testing"

	"github.com/samber/do"
	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services/clients"
	"github.com/willie68/micro-vault/internal/services/groups"
	"github.com/willie68/micro-vault/internal/services/playbook"
	"github.com/willie68/micro-vault/internal/services/storage"
)

var (
	stg interfaces.Storage
	adm Admin
)

func init() {
	var err error
	stg, err = storage.NewFileStorage()
	if err != nil {
		panic(1)
	}
	_, err = groups.NewGroups()
	if err != nil {
		panic(1)
	}
	c := config.Config{
		Service: config.Service{
			Rootuser: "root",
			Rootpwd:  "yxcvb",
		},
	}
	do.ProvideNamedValue[config.Config](nil, config.DoServiceConfig, c)
	_, err = clients.NewClients()
	if err != nil {
		panic(1)
	}
	am, err := NewAdmin()
	if err != nil {
		panic(1)
	}
	adm = am

	installPlaybook()
}

func installPlaybook() {
	stg.Init()
	pb := playbook.NewPlaybookFile("../../../testdata/playbook.json")
	err := pb.Load()
	if err != nil {
		panic(1)
	}
	err = pb.Play()
	if err != nil {
		panic(1)
	}
}

func TestLoginAdmin(t *testing.T) {
	ast := assert.New(t)
	tk, err := adm.LoginUP("root", []byte("yxcvb"))
	ast.Nil(err)
	ast.NotEmpty(tk)
	t.Logf("tk: %s", tk)

	err = adm.checkTk(tk)
	ast.Nil(err)
}
func TestWrongLogin(t *testing.T) {
	ast := assert.New(t)
	tk, err := adm.LoginUP("root1", []byte("yxcvb"))
	ast.NotNil(err)
	ast.Empty(tk)
}

func TestWrongToken(t *testing.T) {
	ast := assert.New(t)
	tk := "eyJhbGciOiJSUzI1NiIsImtpZCI6IndrRVRwcVZiZVpzVWtnRFFLbUNDSmZ6UjdnbjBHdFFVMzFZU0swSmJFZ3MiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsibWljcm92YXVsdC1hZG1pbnMiXSwiZXhwIjoxNjc3Njc1NjIzLCJpYXQiOjE2Nzc2NzUzMjMsInJvbGVzIjpbIm12LWFkbWluIl19.1CtJtXIjL6SLU8RtLF3p7HQSFfW9WHpgVAaQhTEPSXYQm5gMbpr_sR_coW9j_5QCfnDkzKW7OeUmEcWYWiCPgXLCKMRVHGQN9xVUdpl-QOk9fHTyfCiIecrBwHQY0WZY52z2YobNBEelI4PXSc8I44_9UMSj70Z2IzSwmaR6IeGRg0dp9ZNdxQ0-zXGfONP5zepdOWGcnheRhRXBYqz3pPQswjkTfM5R4TG0x1Qwk6zfJbUhMvNsVwJNDqWk5PAbzYMPOUPvumV7XmcBaz_ksr5-mSw7SoCq54Sf4GSyff2v1dbkihywOnabb49MvOSheybUXD-VW3syT1cUawgR4g"
	err := adm.checkTk(tk)
	ast.NotNil(err)

	err = adm.Playbook(tk, model.Playbook{})
	ast.NotNil(err)

	_, err = adm.Groups(tk)
	ast.NotNil(err)

	_, err = adm.AddGroup(tk, model.Group{
		Name: "hello",
	})
	ast.NotNil(err)

	_, err = adm.DeleteGroup(tk, "group3")
	ast.NotNil(err)

	_, err = adm.Clients(tk)
	ast.NotNil(err)

	_, err = adm.DeleteClient(tk, "hello")
	ast.NotNil(err)

	_, err = adm.NewClient(tk, "hello", []string{"group1"})
	ast.NotNil(err)
}

func TestPlaybook(t *testing.T) {
	ast := assert.New(t)
	err := stg.Init()
	ast.Nil(err)
	tk, err := adm.LoginUP("root", []byte("yxcvb"))
	ast.Nil(err)
	ast.NotEmpty(tk)

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
	err = adm.Playbook(tk, pm)
	ast.Nil(err)

	gs, err := adm.Groups(tk)
	ast.Nil(err)
	ast.Equal(2, len(gs))

	cs, err := adm.Clients(tk)
	ast.Nil(err)
	ast.Equal(2, len(cs))
}

func TestGroup(t *testing.T) {
	ast := assert.New(t)
	installPlaybook()

	tk, err := adm.LoginUP("root", []byte("yxcvb"))
	ast.Nil(err)
	ast.NotEmpty(tk)

	gs, err := adm.Groups(tk)
	ast.Nil(err)

	gp := model.Group{
		Name: "group5",
		Label: map[string]string{
			"de": "Gruppe 5",
			"en": "Group 5",
		},
	}

	id, err := adm.AddGroup(tk, gp)

	ast.Nil(err)
	ast.NotEmpty(id)
	ast.True(adm.HasGroup(tk, id))

	g, err := adm.Group(tk, id)
	ast.Nil(err)
	ast.NotNil(g)
	ast.Equal(gp.Name, g.Name)

	ast.True(adm.stg.HasGroup(id))
	gs2, err := adm.Groups(tk)
	ast.Nil(err)
	ast.Equal(len(gs)+1, len(gs2))

	ok, err := adm.DeleteGroup(tk, "group5")
	ast.Nil(err)
	ast.True(ok)

	ast.False(adm.stg.HasGroup(id))

	gs2, err = adm.Groups(tk)
	ast.Nil(err)
	ast.Equal(len(gs), len(gs2))
}

func TestClientCRUD(t *testing.T) {
	ast := assert.New(t)
	tk, err := adm.LoginUP("root", []byte("yxcvb"))
	ast.Nil(err)
	ast.NotEmpty(tk)

	cl, err := adm.NewClient(tk, "client1", []string{"group1"})
	ast.Nil(err)
	ast.NotNil(cl)

	cle, err := adm.NewClient(tk, "client1", []string{"group1"})
	ast.NotNil(err)
	ast.Nil(cle)

	cls, err := adm.Clients(tk)
	ast.Nil(err)
	ast.True(len(cls) > 0)

	cl2, err := adm.Client(tk, "client1")
	ast.Nil(err)
	ast.Equal(cl.Name, cl2.Name)
	ast.Equal(cl.AccessKey, cl2.AccessKey)
	ast.Empty(cl2.Secret)

	ok, err := adm.DeleteClient(tk, "client1")
	ast.Nil(err)
	ast.True(ok)

	ok, err = adm.DeleteClient(tk, "client1")
	ast.NotNil(err)
	ast.False(ok)
}
