package send

import (
	"log"
	"net"
	"net/url"
	"strconv"
)

type NextMsg struct {
    Addr string
    Auth string
}

var (
	nextloop []NextMsg
)

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
		client,err := NewMsgClient(nextloop[i].Addr, nextloop[i].Auth)
		if err !=nil {
		log.Println("Client init err",err)
		continue;
		}
		_,err=client.Send("data", newMsg)
		client.Close()
		if err !=nil {
		log.Println("send err",err)
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