package storage

import (
	"testing"

	"github.com/samber/do"
	"github.com/stretchr/testify/assert"
	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/interfaces"
)

func TestFactoryMemory(t *testing.T) {
	ast := assert.New(t)

	cfg := config.Storage{
		Type: "memory",
	}

	stg, err := NewStorage(cfg)
	ast.Nil(err)

	_, ok := stg.(*Memory)
	ast.True(ok)
	do.MustShutdownNamed(nil, interfaces.DoStorage)
	defer stg.Close()
}

func TestFactoryFS(t *testing.T) {
	ast := assert.New(t)

	cfg := config.Storage{
		Type: "filestorage",
		Properties: map[string]any{
			"path": "../../../testdata/filestorage",
		},
	}

	stg, err := NewStorage(cfg)
	ast.Nil(err)

	_, ok := stg.(*FileStorage)
	ast.True(ok)
	do.MustShutdownNamed(nil, interfaces.DoStorage)
	defer stg.Close()
}

func TestFactoryFSError(t *testing.T) {
	ast := assert.New(t)

	cfg := config.Storage{
		Type:       "filestorage",
		Properties: map[string]any{},
	}

	_, err := NewStorage(cfg)
	ast.NotNil(err)

	cfg.Properties["path"] = 1234
	_, err = NewStorage(cfg)
	ast.NotNil(err)
}
