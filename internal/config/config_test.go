package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samber/do"
	"github.com/stretchr/testify/assert"
)

const (
	serviceLocalFile = "./../../testdata/service_local_file.yaml"
	logFile          = "file.log"
)

func TestLoadFromYaml(t *testing.T) {
	ast := assert.New(t)
	File = serviceLocalFile

	err := Load()
	ast.Nil(err)

	c := Get()

	ast.Equal(8000, c.Service.HTTP.Port)
	ast.Equal(8443, c.Service.HTTP.Sslport)

	ast.Equal(60, c.HealthCheck.Period)
	ast.Equal("", c.SecretFile)
	ast.Equal("https://localhost:8443", c.Service.HTTP.ServiceURL)

	c.Provide()

	cfg := do.MustInvokeNamed[Config](nil, DoServiceConfig)
	ast.Nil(err)
	ast.NotNil(cfg)
	do.MustShutdownNamed(nil, DoServiceConfig)
}

func TestDefaultConfig(t *testing.T) {
	ast := assert.New(t)
	config = DefaultConfig
	cnf := Get()

	ast.Equal(8000, cnf.Service.HTTP.Port)
	ast.Equal(8443, cnf.Service.HTTP.Sslport)

	ast.Equal(30, cnf.HealthCheck.Period)
	ast.Equal("", cnf.SecretFile)
	ast.Equal("https://127.0.0.1:8443", cnf.Service.HTTP.ServiceURL)

	ast.Equal("INFO", cnf.Logging.Level)
}

func TestCfgSubst(t *testing.T) {
	ast := assert.New(t)

	File = filepath.Join("${configdir}", "service_local_file.yaml")

	err := Load()
	ast.NotNil(err)
	home, err := os.UserConfigDir()
	ast.Nil(err)
	file := filepath.Join(home, Servicename, "service_local_file.yaml")
	ast.Equal(file, File)
}

func TestEnvSubstRightCase(t *testing.T) {
	ast := assert.New(t)

	err := os.Setenv("logfile", logFile)
	ast.Nil(err)

	File = serviceLocalFile

	err = Load()
	ast.Nil(err)

	ast.Equal(logFile, Get().Logging.Filename)
}

func TestEnvSubstWrongCase(t *testing.T) {
	ast := assert.New(t)

	err := os.Setenv("LogFile", logFile)
	ast.Nil(err)

	File = "./../../testdata/service_local_file.yaml"

	err = Load()
	ast.Nil(err)

	ast.Equal(logFile, Get().Logging.Filename)
}

func TestSecretMapping(t *testing.T) {
	ast := assert.New(t)

	File = "./../../testdata/service_local_file_w_secret.yaml"

	err := Load()
	ast.Nil(err)

	ast.Equal(120, Get().HealthCheck.Period)
}
