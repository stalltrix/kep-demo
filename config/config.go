package config

import (
    "encoding/json"
    "os"
)

type Neighbor struct {
    URL   string `json:"url"`
    Token string `json:"token"`
}

type Config struct {
    MainKey   string     `json:"mainkey"`
    PubKey    string     `json:"pub_key"`
    PrivKey   string     `json:"priv_key"`
    SigKey    string     `json:"sig_key"`
    Domain    string     `json:"domain"`
	ApiToken     string     `json:"api_token"`
	Listen    string     `json:"listen"`
    Neighbors []Neighbor `json:"neighbors"`
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