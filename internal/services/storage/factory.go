package storage

import (
	"encoding/json"
	"errors"

	"github.com/willie68/micro-vault/internal/config"
	"github.com/willie68/micro-vault/internal/interfaces"
)

// NewStorage creates a new storage based on the configuration
func NewStorage(s config.Storage) (interfaces.Storage, error) {
	var stg interfaces.Storage
	var err error
	logger.Infof("config: storage: %s", s.Type)
	switch s.Type {
	case "memory":
		stg, err = NewMemory()
	case "filestorage":
		p, ok := s.Properties["path"]
		if !ok {
			return nil, errors.New("missing path for file storage")
		}
		path, ok := p.(string)
		if !ok {
			return nil, errors.New("wrong type of path for file storage")
		}
		stg, err = NewFileStorage(path)
		if err != nil {
			return nil, err
		}
	case "mongodb":
		var js []byte
		js, err = json.Marshal(s.Properties)
		if err != nil {
			return nil, err
		}
		var mdcfg MongoDBConfig
		err = json.Unmarshal(js, &mdcfg)
		if err != nil {
			return nil, err
		}
		stg, err = NewMongoStorage(mdcfg)
	}
	return stg, err
}
