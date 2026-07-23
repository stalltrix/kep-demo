package verify

import (
    "os"
	"net"
	"time"
	"errors"
	"context"
	"strings"
	"net/url"
	"net/http"
	"sync/atomic"
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

type _localDNS struct {
    dnsRecord map[string][]string
    lastupdate int64
	lasttime int64
}

const dnsTypeTXT = 16

var (
	custom_dns string
	ErrServer = errors.New("dns server bad status")
	ErrFormat = errors.New("dns server format err")
	ErrNull = errors.New("no txt record")
	localDNS _localDNS
	localAndDNS bool
	lock     atomic.Bool
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
	} else if strings.HasPrefix(custom_dns,"local:"){
		if localDNS.lastupdate+300 < time.Now().Unix() {
			err:=update_localDNS(strings.TrimPrefix(custom_dns,"local:"))
			if err!=nil {
				return nil,err
			}
		}
		txts,ok:=localDNS.dnsRecord[domain]
		if !ok {
			if !localAndDNS {
				return nil,ErrNull
			}
			return net.LookupTXT(domain)
		}
		return txts,nil
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return userDNS.LookupTXT(ctx,domain)
}

func update_localDNS(localfile string) error {
	ok := lock.CompareAndSwap(false, true)
	if !ok {
		return nil
	}
	defer lock.Store(false)
	info, err := os.Stat(localfile)
	if err !=nil {
		return err
	}
	lasttime:=info.ModTime().Unix()
	if localDNS.lasttime==lasttime {
		localDNS.lastupdate=time.Now().Unix()
		return nil
	}
	localDNS.lasttime=lasttime
	data, err := os.ReadFile(localfile)
    if err != nil {
        return err
    }
	str1:= strings.ReplaceAll(string(data), "\r", "")
	str1= strings.ReplaceAll(str1, "\t", " ")
	lines := strings.Split(str1,"\n")
	newRecord:=make(map[string][]string)
	for _, line := range lines {
		if strings.HasPrefix(line,"#"){
			continue
		}
		p := strings.SplitN(line, " ", 2)
		if len(p)!=2 {
			continue
		}
		p[1]=strings.TrimSpace(p[1])
		v,ok:=newRecord[p[0]]
		if !ok {
			newRecord[p[0]]=[]string{p[1]}
			continue
		}
		v=append(v,p[1])
		newRecord[p[0]]=v
	}
	localDNS.dnsRecord=newRecord
	localDNS.lastupdate=time.Now().Unix()
	return nil
}

func SET_DNS_SERVER(addr string) error {
	if addr=="" {
		return nil
	}
	if strings.HasPrefix(addr,"local:")||strings.HasPrefix(addr,"local+dns:"){
		var files string
		if strings.HasPrefix(addr,"local:") {
			files=strings.TrimPrefix(addr,"local:")
			localAndDNS=false
		} else {
			files=strings.TrimPrefix(addr,"local+dns:")
			localAndDNS=true
		}
		err:=update_localDNS(files)
		if err!=nil {
			return err
		}
		custom_dns="local:"+files
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