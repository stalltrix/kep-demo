package send

import (
	"github.com/stalltrix/kep-demo/logger"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"
	"errors"
	"math"
)

type NextMsg struct {
    Addr string
    Auth string
}

type unaliveTables struct {
    failNum int
    wait int
}

type fullTables struct {
    id int
    表 *unaliveTables
}

var (
	nextloop []NextMsg
	blacklist sync.Map
	ttl = time.Second*16
	logDebug logger.Log_TYPE
	logInfo logger.Log_TYPE
	logWarn logger.Log_TYPE
	alivelist sync.Map
	globalSkipSSLchk bool
	失效List sync.Map
	检查中 sync.Map
	后台chk sync.Once
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

func fail(addr,auth string,i int) {
	blacklist.Store(addr, time.Now().Add(ttl))
	set_aliveFail(i)
}

func change_Packet(Msg []byte) []byte {
	length:=len(Msg)
	if length <2{
		return nil
	}
	ttl:=Msg[length-1]
	ttl--
	if ttl ==0 || ttl > 250 {
		return nil
	}
	Msg[length-1]=ttl
    return Msg
}

func is_alive(id int) bool{
	_,ok:= alivelist.Load(id)
	return ok
}

func Maxwait(x int) int {
	y := 599999*math.Exp(0.3*float64(-x))
    z := 600000.0/(1 + y)
    return int(z)
}

func chk_alive(id int) error {
	if len(nextloop) <= id||id<0 {
		return strconv.ErrRange
	}
	err:=Ping(nextloop[id].Addr,nextloop[id].Auth,globalSkipSSLchk)
	if err!=nil{
		return err
	}
	return nil
}

func set_aliveFail(id int){
	now:=int(time.Now().Unix())
	if v,loaded:=检查中.LoadOrStore(id,now);loaded {
		lasttime:=v.(int)
		if now-lasttime < 180 {
			return
		} else {
			检查中.Store(id,now)
		}
	}
	time.AfterFunc(10*time.Second, func() {
		if err:=chk_alive(id);err!=nil {
			time.AfterFunc(40*time.Second, func() {
				if err:=chk_alive(id);err!=nil {
					if _,ok:= alivelist.Load(id);ok{
						alivelist.Delete(id)
						失效List.Store(id,&unaliveTables{
							failNum: 0,
							wait: 300,
						})
					}
				}
				检查中.Delete(id)
			})
		} else {
			检查中.Delete(id)
		}
    })
}

func recover_node(){
	ticker := time.NewTicker(2 * time.Minute)
    defer ticker.Stop()
	for range ticker.C {
		var 全表 []fullTables
		失效List.Range(func(k,v interface{}) bool {
			id:=k.(int)
			table:=v.(*unaliveTables)
			全表=append(全表,fullTables{
				id:id,
				表:table,
			})
			return true
		})
		
		for _,sub:=range 全表 {
			表:=sub.表
			id:=sub.id
			
			表.wait-=120;
			if 表.wait <=0 {
				if err:=chk_alive(id);err!=nil {
					if 表.failNum < 512 {
						表.failNum++
					}
					表.wait=100+Maxwait(表.failNum)
				} else {
					alivelist.Store(id,struct{}{})
					失效List.Delete(id)
				}
			}
		}
	}
}

func auto_chk(){
	for i:=range nextloop {
		alivelist.Store(i,struct{}{})
	}
	ticker := time.NewTicker(30 * time.Minute)
    defer ticker.Stop()
	
	for i:=range nextloop {
		err:=chk_alive(i)
		if err!=nil {
			set_aliveFail(i)
			logDebug.Println("check alive fail:",err)
		}
	}
	
    for range ticker.C {
		var idlist []int
        alivelist.Range(func(k,v interface{}) bool {
			id:=k.(int)
			idlist=append(idlist,id)
			return true
		})
		
		for _,v:=range idlist {
			err:=chk_alive(v)
			if err!=nil {
				set_aliveFail(v)
				logDebug.Println("check alive fail:",err)
			}
		}
    }
}

func Ping(addr,auth string,skipSSLchk bool) error {
	client,err := NewMsgClient(addr,auth,skipSSLchk)
	if err !=nil {
		return err
	}
	body,err:=client.Send("ping", nil)
	if err !=nil {
		return err
	}
	if string(body) != "+PONG" {
		return errors.New(addr+" recv data != PONG")
	}
	return nil
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
		if !is_alive(i) {
			logDebug.Println("skip unreachable neighbor",nextloop[i].Addr)
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
		fail(nextloop[i].Addr,nextloop[i].Auth,i)
		continue;
		}
		if string(body)!="+OK"{
		logWarn.Println("send err with resp")
		fail(nextloop[i].Addr,nextloop[i].Auth,i)
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

func Send_Init(nextServer []NextMsg,socks5addr string,skipSSLchk bool) {
	nextloop=nextServer
	globalSkipSSLchk=skipSSLchk
	后台chk.Do(func(){
		go auto_chk()
		go recover_node()
	})
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