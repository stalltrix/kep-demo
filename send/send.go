package send

import (
	"github.com/stalltrix/kep-demo/logger"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"
	"errors"
)

type NextMsg struct {
    Addr string
    Auth string
}

var (
	nextloop []NextMsg
	blacklist sync.Map
	ttl = time.Minute
	logDebug logger.Log_TYPE
	logInfo logger.Log_TYPE
	logWarn logger.Log_TYPE
)

func init() {
    logDebug.SetLevel("debug")
	logInfo.SetLevel("info")
	logWarn.SetLevel("warn")
}

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

func Nextmsg(msg []byte,self string,skipSSLchk bool) error {
	newMsg:=change_Packet(msg)
	if newMsg == nil {
		return nil
	}
	success:=0
	for i:=range nextloop {
		if self==nextloop[i].Auth{
			continue;
		}
		if !allow(nextloop[i].Addr) {
			logInfo.Println("skip fail neighbor url",nextloop[i].Addr)
			continue;
		}
		client,err := NewMsgClient(nextloop[i].Addr, nextloop[i].Auth,skipSSLchk)
		if err !=nil {
		logWarn.Println("Client init err",err)
		continue;
		}
		body,err:=client.Send("data", newMsg)
		if err !=nil {
		logWarn.Println("send err",err)
		fail(nextloop[i].Addr)
		continue;
		}
		if string(body)!="+OK"{
		logWarn.Println("send err with resp")
		fail(nextloop[i].Addr)
		continue;
		}
		logDebug.Println("send to",nextloop[i].Addr)
		success++
	}
	if success == 0 {
		return errors.New("success=0")
	}
	return nil
}

func Send_Init(nextServer []NextMsg,socks5addr string) {
	nextloop=nextServer
	if socks5addr != "" {
	u, err := url.Parse("scheme://" + socks5addr)
    if err != nil {
		logWarn.Println("socks5 addr err, skip", err)  
        return
    }
	if u.User != nil {
        socks_user = u.User.Username()
        socks_pass, _ = u.User.Password()
    }
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		logWarn.Println("socks5 addr err, skip",err)
		return
	}
	p, err := strconv.Atoi(port)
    if err != nil || p < 1 || p > 65535 {
        logWarn.Println("socks5: invalid port")
        return
    }
	if host == "" {
		logWarn.Println("socks5: host==\"\"")
        return
	}
	proxyAddr= net.JoinHostPort(host, port)
	logDebug.Println("set socks5:",proxyAddr)
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