package config

import (
    "encoding/json"
    "os"
)

type Neighbor struct {
    URL   string `json:"url"`
    Token string `json:"token"`
	RPM   int    `json:"rpm"`
}

type Config struct {
	ApiToken     string     `json:"api_token"`
	Apiport     string     `json:"api_port"`
	Listen    string     `json:"listen"`
	Ntp    string     `json:"ntp"`
	Socks5    string     `json:"socks5"`
	LogLevel string      `json:"log_level"`
	Skiptoken  string     `json:"local_token"`
	File_deny    string     `json:"deny_file"`
	File_token    string     `json:"token_file"`
}

func Resolv(filename string) (Config,error) {
	var cfg Config
    data, err := os.ReadFile(filename)
    if err != nil {
        return cfg,err
    }
    err = json.Unmarshal(data, &cfg)
    if err != nil {
        return cfg,err
    }
    return cfg,nil
}