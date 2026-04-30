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

type CustomData struct {
    HTTPCode    int    `json:"http-code"`
    ContentType string `json:"content-type"`
    Pages_file       string `json:"resp_file"`
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
	Custom404   string     `json:"custom_file404"`
	CustomIdx   string     `json:"custom_fileIdx"`
	Archive     string     `json:"archive"`
	Crt  string     `json:"crt"`
	Key  string     `json:"key"`
	CustomAPI CustomData `json:"custom404"`
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