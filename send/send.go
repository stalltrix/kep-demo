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
	"sync/atomic"
)

type NextMsg struct {
    Addr string
    Auth string
}

type unaliveTables struct {
    failNum int
    wait int
	auth string
}

type fullTables struct {
    addr string
    表 *unaliveTables
}

type stateTables struct {
    black atomic.Int32
	alive atomic.Bool
    tm atomic.Int64
	auth string
}

var (
	nextloop []NextMsg
	stateList sync.Map
	ttl = time.Second*30
	logDebug logger.Log_TYPE
	logInfo logger.Log_TYPE
	logWarn logger.Log_TYPE
	globalSkipSSLchk bool
	失效List sync.Map
	检查中 sync.Map
	后台chk sync.Once
	Custom_userAgent string
	Custom_header map[string]string
)

func init() {
    logDebug.SetLevel("debug")
	logInfo.SetLevel("info")
	logWarn.SetLevel("warn")
}

func allowAndalive(addr string) (bool,bool) {
    v, ok := stateList.Load(addr)
    if !ok {
        return true,false //allow,is_alive
    }
	
	状态:=v.(*stateTables)
	
	allowd:=状态.black.Load()<2
	alived:=状态.alive.Load()
	
	if !allowd {
		expire := 状态.tm.Load()
		if time.Now().Unix()>expire {
			状态.black.Store(0)
			allowd=true
		}
	}
	
    return allowd,alived
}

func fail(addr,auth string) {
	v,ok:=stateList.Load(addr)
	if ok {
		状态:=v.(*stateTables)
		状态.black.Add(1)
		状态.tm.Store(time.Now().Add(ttl).Unix())
	}
	set_aliveFail(addr,auth)
}

func succeed(addr string){
	v,ok:=stateList.Load(addr)
	if ok {
		状态:=v.(*stateTables)
		if 状态.black.Load()!=0 {
			状态.black.Store(0)
		}
	}
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

func Maxwait(x int) int {
	y := 32700*math.Exp(0.3*float64(-x))
    z := 600000.0/(1 + y)
    return int(z)
}

func chk_alive(addr,auth string) error {
	return Ping(addr,auth,globalSkipSSLchk)
}

func set_aliveFail(addr,auth string){
	now:=int(time.Now().Unix())
	if v,loaded:=检查中.LoadOrStore(addr,now);loaded {
		lasttime:=v.(int)
		if now-lasttime < 180 {
			return
		} else {
			检查中.Store(addr,now)
		}
	}
	time.AfterFunc(10*time.Second, func() {
		if err:=chk_alive(addr,auth);err!=nil {
			time.AfterFunc(40*time.Second, func() {
				if err:=chk_alive(addr,auth);err!=nil {
					if v,ok:= stateList.Load(addr);ok{
						状态:=v.(*stateTables)
						状态.alive.Store(false)
						失效List.Store(addr,&unaliveTables{
							failNum: 0,
							wait: 300,
							auth: auth,
						})
					}
				}
				检查中.Delete(addr)
			})
		} else {
			检查中.Delete(addr)
		}
    })
}

func recover_node(){
	ticker := time.NewTicker(2 * time.Minute)
    defer ticker.Stop()
	for range ticker.C {
		var 全表 []fullTables
		失效List.Range(func(k,v interface{}) bool {
			addr:=k.(string)
			table:=v.(*unaliveTables)
			全表=append(全表,fullTables{
				addr:addr,
				表:table,
			})
			return true
		})
		
		for _,sub:=range 全表 {
			表:=sub.表
			addr:=sub.addr
			
			表.wait-=120;
			if 表.wait <=0 {
				if err:=chk_alive(addr,表.auth);err!=nil {
					if 表.failNum < 64 {
						表.failNum++
					}
					表.wait=100+Maxwait(表.failNum)
				} else {
					失效List.Delete(addr)
					v,ok:=stateList.Load(addr)
					if ok {
						状态:=v.(*stateTables)
						状态.alive.Store(true)
					}
				}
			}
		}
	}
}

func auto_chk(){
	for i:=range nextloop {
		if nextloop[i].Addr==""{
			continue;
		}
		v,ok:=stateList.Load(nextloop[i].Addr)
		if !ok {
			v,_=stateList.LoadOrStore(nextloop[i].Addr,&stateTables{})
		}
		状态:=v.(*stateTables)
		状态.alive.Store(true)
		状态.auth=nextloop[i].Auth
	}
	ticker := time.NewTicker(30 * time.Minute)
    defer ticker.Stop()
	
	for i:=range nextloop {
		if nextloop[i].Addr==""{
			continue;
		}
		err:=chk_alive(nextloop[i].Addr,nextloop[i].Auth)
		if err!=nil {
			set_aliveFail(nextloop[i].Addr,nextloop[i].Auth)
			logDebug.Println("check alive fail:",err)
		}
	}
	
    for range ticker.C {
		var NerList []NextMsg
        stateList.Range(func(k,v interface{}) bool {
			addr:=k.(string)
			状态:=v.(*stateTables)
			if 状态.alive.Load() {
				NerList=append(NerList,NextMsg{
					Addr:addr,
					Auth:状态.auth,
				})
			}
			return true
		})
		
		for _,v:=range NerList {
			err:=chk_alive(v.Addr,v.Auth)
			if err!=nil {
				set_aliveFail(v.Addr,v.Auth)
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
	if Custom_userAgent!=""{
		client.UserAgent=Custom_userAgent
	}
	if len(Custom_header)>0{
		client.Headers=Custom_header
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
	for _,svc:=range nextloop {
		if svc.Addr==""{
			continue;
		}
		if self==svc.Auth{
			continue;
		}
		allow,alive:=allowAndalive(svc.Addr)
		if !alive {
			logDebug.Println("skip unreachable neighbor",svc.Addr)
			continue;
		}
		if !allow {
			logInfo.Println("skip fail neighbor url",svc.Addr)
			continue;
		}
		client,err := NewMsgClient(svc.Addr, svc.Auth,skipSSLchk)
		if err !=nil {
		logWarn.Println("Client init err",err)
		continue;
		}
		if Custom_userAgent!=""{
			client.UserAgent=Custom_userAgent
		}
		if len(Custom_header)>0{
			client.Headers=Custom_header
		}
		body,err:=client.Send("data", newMsg)
		if err !=nil {
		logWarn.Println("send err",err)
		fail(svc.Addr,svc.Auth)
		continue;
		}
		if string(body)!="+OK"{
		logWarn.Println("send err with resp")
		fail(svc.Addr,svc.Auth)
		continue;
		}
		succeed(svc.Addr)
		logDebug.Println("send to",svc.Addr)
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
	if addr==""{
		return
	}
	new_next :=NextMsg{
		Addr: addr,
		Auth: token,
	}
	nextloop=append(nextloop,new_next)
	
	v,ok:=stateList.Load(addr)
	if !ok {
		v,_=stateList.LoadOrStore(addr,&stateTables{})
	}
	状态:=v.(*stateTables)
	状态.alive.Store(true)
	状态.auth=token
}

func Remove(token string) {
	var res []NextMsg
    for _, v := range nextloop {
        if v.Auth != token {
            res = append(res, v)
        } else {
			stateList.Delete(v.Addr)
			失效List.Delete(v.Addr)
		}
    }
	nextloop=res
    return
}