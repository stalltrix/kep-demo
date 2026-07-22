package verify

import (
    "net"
	"time"
	"errors"
	"context"
	"strings"
	"net/url"
	"net/http"
	"encoding/json"
)

type DoHAnswer struct {
    Name string `json:"name"`
    Type int    `json:"type"`
    TTL  int    `json:"TTL"`
    Data string `json:"data"`
}

type DoHResponse struct {
    Status int `json:"Status"`
    Answer []DoHAnswer `json:"Answer"`
}

const dnsTypeTXT = 16

var (
	custom_dns string
	ErrServer = errors.New("dns server bad status")
	ErrFormat = errors.New("dns server format err")
	ErrNull = errors.New("no txt record")
)

var client = &http.Client{
    Timeout: 16 * time.Second,
}

var userDNS = &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
            d := net.Dialer{
                Timeout: time.Second * 8,
            }
            return d.DialContext(ctx, "udp", custom_dns)
        },
}

func NSLookupTXT(domain string)([]string, error){
	if custom_dns==""{
		return net.LookupTXT(domain)
	}
	if strings.HasPrefix(custom_dns,"http"){
		endpoint := custom_dns+"?name="+url.QueryEscape(domain)+"&type=TXT"
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return nil,err
		}
		req.Header.Set("Accept", "application/dns-json")
		req.Header.Set("User-Agent","")
		resp, err := client.Do(req)
		if err != nil {
			return nil,err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil,ErrServer
		}
		var result DoHResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			return nil,err
		}
		if result.Status != 0 {
			return nil, ErrServer
		}
		if len(result.Answer)==0{
			return nil, ErrNull
		}
		txts := make([]string, 0, len(result.Answer))
		for _, ans := range result.Answer {
			if ans.Type != dnsTypeTXT {
				continue
			}
			if len(ans.Data)>2 && ans.Data[0]=='"' && ans.Data[len(ans.Data)-1]=='"' {
                ans.Data=ans.Data[1:len(ans.Data)-1]
            }
			if ans.Data != "" {
				txts = append(txts, ans.Data)
			}
		}
		if len(txts) == 0 {
			return nil, ErrNull
		}
		return txts, nil
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return userDNS.LookupTXT(ctx,domain)
}

func SET_DNS_SERVER(addr string) error {
	if addr=="" {
		return nil
	}
	if strings.HasPrefix(addr,"http://")||strings.HasPrefix(addr,"https://"){
		u, err := url.ParseRequestURI(addr)
		if err != nil {
			return err
		}
		if u.Scheme == "" || u.Host == "" {
			return ErrFormat
		}
		custom_dns=addr
		return nil
	}
	
	host, port, err := net.SplitHostPort(addr)
    if err != nil {
        return err
    }
    ip := net.ParseIP(host)
    if ip == nil {
        return ErrFormat
    }
    p, err := net.LookupPort("tcp", port)
    if err != nil {
        return err
    }
    if p < 0 || p > 65535 {
		return ErrFormat
	}
	custom_dns=addr
	return nil
}