package client

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/pkg/pmodel"
)

var (
	adm *AdminCl
)

func init() {
	ad, err := LoginAdminUP("root", []byte("yxcvb"), "https://127.0.0.1:9543")
	if err != nil {
		panic(err)
	}
	adm = ad
}

func TestAdmPlaybook(t *testing.T) {
	ast := assert.New(t)
	ast.NotNil(adm)

	pm := model.Playbook{
		Groups: []model.Group{
			model.Group{
				Name: "group4",
				Label: map[string]string{
					"de": "Gruppe 4",
					"en": "Group 4",
				},
			},
		},
		Clients: []model.Client{
			model.Client{
				Name:      "tester4",
				AccessKey: "1234567890",
				Secret:    "0987654321",
				Groups:    []string{"group1", "group3"},
			},
		},
	}
	js, err := json.Marshal(pm)
	ast.Nil(err)
	err = adm.SendPlaybook(string(js))
	ast.Nil(err)

	gs, err := adm.Groups()
	ast.Nil(err)
	found := false
	for _, g := range gs {
		if g.Name == "group4" {
			found = true
		}
	}
	ast.True(found)

	cs, err := adm.Clients()
	ast.Nil(err)
	found = false
	for _, c := range cs {
		if c.Name == "tester4" && c.AccessKey == "1234567890" {
			found = true
		}
	}
	ast.True(found)
}

func TestAdmNewClient(t *testing.T) {
	ast := assert.New(t)
	ast.NotNil(adm)

	cl, err := adm.NewClient("tester5", []string{"group1", "group3"})

	ast.Nil(err)
	ast.NotNil(cl)
	ast.NotEmpty(cl.AccessKey)
	ast.NotEmpty(cl.Secret)
	ast.Equal("tester5", cl.Name)

	cl, err = adm.NewClient("tester5", []string{"group1", "group3"})

	ast.NotNil(err)
	ast.Nil(cl)

}

func TestAdmCRUDGroup(t *testing.T) {
	ast := assert.New(t)
	ast.NotNil(adm)

	gs, err := adm.Groups()
	ast.Nil(err)
	ast.True(len(gs) > 0)

	err = adm.AddGroup(pmodel.Group{
		Name: "group5",
		Label: map[string]string{
			"de": "Gruppe 5",
			"en": "Group 5",
		},
	})

	g, err := adm.Group("group5")
	ast.Nil(err)
	ast.Equal("group5", g.Name)
	ast.Equal("Gruppe 5", g.Label["de"])

	gs2, err := adm.Groups()
	ast.Nil(err)
	ast.Equal(len(gs)+1, len(gs2))

	err = adm.DeleteGroup("group5")
	ast.Nil(err)

	gs2, err = adm.Groups()
	ast.Nil(err)
	ast.Equal(len(gs), len(gs2))
}
