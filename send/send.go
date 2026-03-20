package send

import (
	"log"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type NextMsg struct {
    Addr string
    Auth string
}

var (
	nextloop []NextMsg
	blacklist sync.Map
	ttl = time.Minute
)

func allow(addr string) bool {
    v, ok := blacklist.Load(addr)
    if !ok {
        return true
    }

    expire := v.(time.Time)
    if time.Now().After(expire) {
        blacklist.Delete(addr)
        return true
    }

    return false
}

func fail(addr string) {
    blacklist.Store(addr, time.Now().Add(ttl))
}

func change_Packet(Msg []byte) []byte {
	length:=len(Msg)
	ttl:=Msg[length-1]
	ttl--
	if ttl ==0 || ttl > 250 {
		return nil
	}
	Msg[length-1]=ttl
    return Msg
}

func Nextmsg(msg []byte,self string) error {
	newMsg:=change_Packet(msg)
	if newMsg == nil {
		return nil
	}
	for i:=range nextloop {
		if self==nextloop[i].Auth{
			continue;
		}
		if !allow(nextloop[i].Addr) {
			log.Println("skip fail neighbor url",nextloop[i].Addr)
			continue;
		}
		client,err := NewMsgClient(nextloop[i].Addr, nextloop[i].Auth)
		if err !=nil {
		log.Println("Client init err",err)
		continue;
		}
		body,err:=client.Send("data", newMsg)
		client.Close()
		if err !=nil {
		log.Println("send err",err)
		fail(nextloop[i].Addr)
		continue;
		}
		if string(body)!="+OK"{
		log.Println("send err with resp")
		fail(nextloop[i].Addr)
		continue;
		}
		log.Println("send to",nextloop[i].Addr)
	}
	return nil
}

func Send_Init(nextServer []NextMsg,socks5addr string) {
	nextloop=nextServer
	if socks5addr != "" {
	u, err := url.Parse("scheme://" + socks5addr)
    if err != nil {
		log.Println("socks5 addr err, skip", err)  
        return
    }
	if u.User != nil {
        socks_user = u.User.Username()
        socks_pass, _ = u.User.Password()
    }
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		log.Println("socks5 addr err, skip",err)
		return
	}
	p, err := strconv.Atoi(port)
    if err != nil || p < 1 || p > 65535 {
        log.Println("socks5: invalid port")
        return
    }
	if host == "" {
		log.Println("socks5: host==\"\"")
        return
	}
	proxyAddr= net.JoinHostPort(host, port)
	}
}

func Append(addr,token string) {
	new_next :=NextMsg{
		Addr: addr,
		Auth: token,
	}
	nextloop=append(nextloop,new_next)
}

func Remove(token string) {
	res := nextloop[:0]
    for _, v := range nextloop {
        if v.Auth != token {
            res = append(res, v)
        }
    }
	nextloop=res
    return
}