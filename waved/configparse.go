package waved

import (
	"github.com/BurntSushi/toml"
)

type Configuration struct {
	Database           string
	ListenIP           string
	HTTPListenIP       string
	ListenUnix         string
	DefaultToUnrevoked bool
	Storage            map[string]map[string]string
}

func ParseConfig(file string) (*Configuration, error) {
	var conf Configuration
	if _, err := toml.DecodeFile(file, &conf); err != nil {
		return nil, err
	}
	return &conf, nil
}
