package admin

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/interfaces"
	"github.com/willie68/micro-vault/internal/model"
	"github.com/willie68/micro-vault/internal/services/clients"
	"github.com/willie68/micro-vault/internal/services/groups"
	"github.com/willie68/micro-vault/internal/services/keyman"
	"github.com/willie68/micro-vault/internal/services/playbook"
	"github.com/willie68/micro-vault/internal/services/storage"
)

var (
	stg interfaces.Storage
	adm Admin
)

func init() {
	var err error
	stg, err = storage.NewMemory()
	if err != nil {
		panic(1)
	}
	c := config.Config{
		Service: config.Service{
			Rootuser:   "root",
			Rootpwd:    "yxcvb",
			PrivateKey: "../../../testdata/private.pem",
		},
	}
	c.Provide()
	_, err = keyman.NewKeyman()
	if err != nil {
		panic(1)
	}
	_, err = groups.NewGroups()
	if err != nil {
		panic(1)
	}
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

func TestNewPlaybook(t *testing.T) {
	ast := assert.New(t)
	tk, rt, err := adm.LoginUP("root", []byte("yxcvb"))
	ast.Nil(err)
	ast.NotEmpty(tk)
	ast.NotEmpty(rt)

	cl, err := adm.NewClient(tk, "tester7", []string{"group2", "group4"})
	ast.Nil(err)
	js, err := json.Marshal(cl)
	ast.Nil(err)
	fmt.Println(string(js))
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
	tk, rt, err := adm.LoginUP("root", []byte("yxcvb"))
	ast.Nil(err)
	ast.NotEmpty(tk)
	ast.NotEmpty(rt)
	t.Logf("tk: %s", tk)
	t.Logf("rt: %s", rt)

	err = adm.checkTk(tk)
	ast.Nil(err)

	_, err = adm.checkRtk(rt)
	ast.Nil(err)
}

func TestRefresh(t *testing.T) {
	ast := assert.New(t)
	tk, rt, err := adm.LoginUP("root", []byte("yxcvb"))
	ast.Nil(err)
	ast.NotEmpty(tk)
	ast.NotEmpty(rt)

	gs, err := adm.Groups(tk)
	ast.Nil(err)
	ast.NotNil(gs)

	_, err = adm.Groups(rt)
	ast.NotNil(err)

	tk2, rt2, err := adm.Refresh(rt)
	ast.Nil(err)

	ast.NotEmpty(tk2)
	ast.NotEmpty(rt2)

	gs, err = adm.Groups(tk2)
	ast.Nil(err)
	ast.NotNil(gs)

	_, err = adm.Groups(rt2)
	ast.NotNil(err)

	_, err = adm.checkRtk(rt)
	ast.NotNil(err)

	tk3, rt3, err := adm.Refresh(rt)
	ast.NotNil(err)
	ast.Empty(tk3)
	ast.Empty(rt3)
}

func TestWrongLogin(t *testing.T) {
	ast := assert.New(t)
	tk, _, err := adm.LoginUP("root1", []byte("yxcvb"))
	ast.NotNil(err)
	ast.Empty(tk)
}

func TestWrongToken(t *testing.T) {
	ast := assert.New(t)

	tk := "eyJhbGciOiJSUzI1NiIsImtpZCI6IndrRVRwcVZiZVpzVWtnRFFLbUNDSmZ6UjdnbjBHdFFVMzFZU0swSmJFZ3MiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsibWljcm92YXVsdC1hZG1pbnMiXSwiZXhwIjoxNjc3Njc1NjIzLCJpYXQiOjE2Nzc2NzUzMjMsInJvbGVzIjpbIm12LWFkbWluIl19.1CtJtXIjL6SLU8RtLF3p7HQSFfW9WHpgVAaQhTEPSXYQm5gMbpr_sR_coW9j_5QCfnDkzKW7OeUmEcWYWiCPgXLCKMRVHGQN9xVUdpl-QOk9fHTyfCiIecrBwHQY0WZY52z2YobNBEelI4PXSc8I44_9UMSj70Z2IzSwmaR6IeGRg0dp9ZNdxQ0-zXGfONP5zepdOWGcnheRhRXBYqz3pPQswjkTfM5R4TG0x1Qwk6zfJbUhMvNsVwJNDqWk5PAbzYMPOUPvumV7XmcBaz_ksr5-mSw7SoCq54Sf4GSyff2v1dbkihywOnabb49MvOSheybUXD-VW3syT1cUawgR4g"
	rt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsibWljcm92YXVsdC1hZG1pbnMiXSwiZXhwIjoxNjc5ODQ4NTc4LCJpYXQiOjE2Nzk4NDQ5NzgsInJvbGVzIjpbIm12LXJlZnJlc2giXSwidXNhZ2UiOiJtdi1yZWZyZXNoIn0.MdfUKl2Ew5YUklt5cAnWnDXJUdNjZlf8CNLRMKiQPaVF6Dn0nB8tXM5AVgHXaxgOHzO4MCy99uh2aX9P_3Dh11jk82WZ7avlkmVak79r6JN203Izr42Hr6cJSlxbQ5OPjoO5XMoyKRPR6MA0BC3K8u6Ylm56FFv8z-8fnRwNhPX4eMXgoMx-jc2CVqxUWF5OgxRdxilMiUDQYrkvg5Hh_B8tQPPB9SeYzRrq-F4sYb9ygn_loEZ4PwzKuFdy8Wk7f3q9RYs0GlUsPcL9rvuR4CbtX33DPTk-6XWXsfXTqP5h8kCLpRGcZBPpq1pr6KGKGdJTFzbZQCWjnkW8Ia_e4g"

	err := adm.checkTk(tk)
	ast.NotNil(err)

	_, err = adm.checkRtk(rt)
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

func TestOldToken(t *testing.T) {
	ast := assert.New(t)

	tk := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsibWljcm92YXVsdC1hZG1pbnMiXSwiZXhwIjoxNjc5ODk5OTk1LCJpYXQiOjE2Nzk4OTk2OTUsInJvbGVzIjpbIm12LWFkbWluIl19.IF6f7yHKD8Y5RFnAptNK_LB7AENJb0cCHwk8L7XA979gyThbI6k9qbQlCmPxuxpsJPtzkXMUpzWAhagr11OmRC5Xffaq-bt-eqA2FK7goDmRLy2ZM13SWDmlNulIcZmqUpJBsvHFPEN2kve3aM0aNAjd5FTSjpCuarOtlsw9ykQAETwEaspcXqx16i9KjYznQo9P92KNwnapNEghmWTnjjhQ0pNe0jUuxNoxc0wvt_f0W36rQQVtCvCrgvsbYH2PR_3bqMNx1B7nbVPYyZxR2LjVU2bZ-XO4McAHEOO4sNZx64qGFkC2MJJ5G4nJ1zXMjdQk6WrRpHdr1WJhHoW-Hw"
	rt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsibWljcm92YXVsdC1hZG1pbnMiXSwiZXhwIjoxNjc5OTAzNzY2LCJpYXQiOjE2Nzk5MDAxNjYsInVzYWdlIjoibXYtcmVmcmVzaCJ9.r9GLTkeVVVWJIVBqT9SGHqwdwRIFDw6vmirLfTNF8PdS728xKRYzrkqM40Et5be_S13NjuGDRCfwj5dkb44QF-4cY-KbzEiT2XwmVnJB23qIXHxKFCXSL9Hju_hXfXtlX41kJ4eUHiJHu92ZvEe2-nod6vdr9q5zMBYlKlCX72b7bFOLuNiJcGYax2m4ft1qgZJNkE2FO2aeDHsffOdHqX7-pwJ1D8zp0hFF3QgTzquDlkvab9XWKF9UI00_G2C9IDJSRQNtpRV9C6u5GJMSHnJp15m6u5l104giLKHvxQy68i8fpD_rw2Uu3wL04pRKbTntHmcxmQJ4Y7_Fyx0Fhg"

	err := adm.checkTk(tk)
	ast.NotNil(err)

	_, err = adm.checkRtk(rt)
	ast.NotNil(err)
}

func TestPlaybook(t *testing.T) {
	ast := assert.New(t)
	err := stg.Init()
	ast.Nil(err)
	tk, _, err := adm.LoginUP("root", []byte("yxcvb"))
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
	ast.Equal(4, len(gs))

	cs, err := adm.Clients(tk)
	ast.Nil(err)
	ast.Equal(2, len(cs))
}

func TestGroup(t *testing.T) {
	ast := assert.New(t)
	installPlaybook()

	tk, _, err := adm.LoginUP("root", []byte("yxcvb"))
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
	tk, _, err := adm.LoginUP("root", []byte("yxcvb"))
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

	ast.True(adm.HasGroup(tk, "client1"))

	_, err = adm.AddGroup(tk, model.Group{Name: "client1"})
	ast.NotNil(err)

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

func TestClient4Group(t *testing.T) {
	ast := assert.New(t)
	tk, _, err := adm.LoginUP("root", []byte("yxcvb"))
	ast.Nil(err)
	ast.NotEmpty(tk)

	cs, err := adm.Client4Group(tk, "group1")
	ast.Nil(err)
	ast.NotNil(cs)
	ast.Equal(1, len(cs))
	ast.Equal("tester1", cs[0].Name)
	ast.Equal("group1", cs[0].Groups[0])
}

func TestKeys(t *testing.T) {
	ast := assert.New(t)
	tk, _, err := adm.LoginUP("root", []byte("yxcvb"))
	ast.Nil(err)
	ast.NotEmpty(tk)

	cs, err := adm.Keys(tk, 0, 99)
	ast.Nil(err)
	ast.NotNil(cs)
	ast.Equal(1, len(cs))
	ast.Equal("cghve2g11fjp746madig", cs[0].ID)
	ast.Equal("group1", cs[0].Group)
}

func TestKeys4Group(t *testing.T) {
	ast := assert.New(t)
	stg.Init()
	tk, _, err := adm.LoginUP("root", []byte("yxcvb"))
	ast.Nil(err)
	ast.NotEmpty(tk)

	cnt := 0
	for i := 0; i < 100; i++ {
		idx := rand.Intn(4)
		idx++
		if idx == 1 {
			cnt++
		}
		id := xid.New().String()
		buf := make([]byte, 32)
		_, err = rand.Read(buf)
		ast.Nil(err)

		e := model.EncryptKey{
			ID:      id,
			Alg:     "AES-256",
			Key:     hex.EncodeToString(buf),
			Created: time.Now(),
			Group:   fmt.Sprintf("group%d", idx),
		}
		err = stg.StoreEncryptKey(e)
		ast.Nil(err)
	}

	cs, err := adm.Keys(tk, 0, 100)
	ast.Nil(err)
	ast.NotNil(cs)
	ast.Equal(100, len(cs))

	cs, err = adm.Keys4Group(tk, "group1", 0, 100)
	ast.Nil(err)
	ast.NotNil(cs)
	ast.Equal(cnt, len(cs))
}
