package client

import (
	"encoding/json"
	"testing"

	"slices"

	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/pkg/pmodel"
)

var (
	adm *AdminCl
)

func initAdm() {
	StartServer()
	if adm == nil {
		ad, err := LoginAdminUP("root", []byte("yxcvb"), "https://127.0.0.1:9543")
		if err != nil {
			panic(err)
		}
		adm = ad
	}
}

func TestRefresh(t *testing.T) {
	initAdm()
	ast := assert.New(t)
	ast.NotNil(adm)

	tk := adm.token
	ex := adm.expired
	rt := adm.refreshToken

	_, err := adm.Groups()
	ast.Nil(err)

	err = adm.Refresh()
	ast.Nil(err)

	ast.NotEqual(tk, adm.token)
	ast.NotEqual(rt, adm.refreshToken)
	ast.NotEqual(ex, adm.expired)

	_, err = adm.Groups()
	ast.Nil(err)
}

func TestAdmPlaybook(t *testing.T) {
	initAdm()
	ast := assert.New(t)
	ast.NotNil(adm)
	err := adm.DeleteGroup("group4")
	if err != nil {
		t.Logf("prepare: error delete group: %v", err)
	}
	err = adm.DeleteClient("tester4")
	if err != nil {
		t.Logf("prepare: error delete client: %v", err)
	}

	pm := model.Playbook{
		Groups: []model.Group{
			{
				Name: "group4",
				Label: map[string]string{
					"de": "Gruppe 4",
					"en": "Group 4",
				},
			},
		},
		Clients: []model.Client{
			{
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
	ast.True(slices.ContainsFunc(gs, func(g pmodel.Group) bool {
		return g.Name == "group4"
	}))

	cs, err := adm.Clients()
	ast.Nil(err)
	ast.True(slices.ContainsFunc(cs, func(c pmodel.Client) bool {
		return c.Name == "tester4" && c.AccessKey == "1234567890"
	}))
}

func TestAdmNewClient(t *testing.T) {
	initAdm()
	ast := assert.New(t)
	ast.NotNil(adm)
	// Prepare
	err := adm.DeleteClient("tester5")
	if err != nil {
		t.Logf("prepare: error delete client: %v", err)
	}

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
	initAdm()
	ast := assert.New(t)
	ast.NotNil(adm)
	err := adm.DeleteGroup("group5")
	if err != nil {
		t.Logf("prepare: error delete group: %v", err)
	}

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
	ast.Nil(err)

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
