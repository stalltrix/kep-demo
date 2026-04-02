package main

import (
    "context"
    "crypto/tls"
    "io"
	"github.com/stalltrix/kep-demo/logger"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "syscall"
	"errors"
	"sync"
	"github.com/stalltrix/kep-demo/verify"
	"github.com/stalltrix/kep-demo/send"
	"github.com/stalltrix/kep-demo/kepresolv"
	"time"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
	"github.com/stalltrix/kep-demo/config"
	"encoding/hex"
	"bytes"
	"encoding/json"
	"github.com/stalltrix/kep-demo/ntp"
	"strconv"
)

type tokenLimiter struct {
    limiter   *rate.Limiter
    lastUsed  int64
}

var (
    maxBodySize  = int64(1 << 17) // 128K
    readTimeout  = 60 * time.Second
    writeTimeout = 60 * time.Second
    idleTimeout  = 1800 * time.Second
	token_Map sync.Map
	nextroute []send.NextMsg
	deny_Map map[string]bool
	deny_lock sync.RWMutex
	limiterMap sync.Map
	g_token string
	newMsg_logger sync.Map
	Skip_token string
	logDebug logger.Log_TYPE
	logErr logger.Log_TYPE
	logInfo logger.Log_TYPE
	logWarn logger.Log_TYPE
	logMust logger.Log_TYPE
	custom_page404 []byte
	custom_pageidx []byte
)

func startLimiterCleaner() {
        ticker := time.NewTicker(10 * time.Minute)
        defer ticker.Stop()
        for range ticker.C {
            now := time.Now().Unix()
            limiterMap.Range(func(key, value interface{}) bool {
                tl := value.(*tokenLimiter)
                if now-tl.lastUsed > 7200 {
                    limiterMap.Delete(key)
                }
                return true
            })
        }
}

func getLimiter(token string,is_domain bool) *rate.Limiter {
    now := time.Now().Unix()

    if v, ok := limiterMap.Load(token); ok {
        tl := v.(*tokenLimiter)
        tl.lastUsed = now
        return tl.limiter
    }
	
	var new_rpm *rate.Limiter
	if !is_domain{
	o_rpm, ok := token_Map.Load(token)
	if ok {
		set_rpm:=(o_rpm.(*config.Neighbor)).RPM
		if set_rpm <= 0 {
			set_rpm=10
		}
		new_rpm=rate.NewLimiter(rate.Every(time.Minute/time.Duration(set_rpm)), set_rpm)
	} else {
		new_rpm=rate.NewLimiter(rate.Every(time.Minute/60), 60)
	}}else{
		new_rpm=rate.NewLimiter(rate.Every(time.Minute/20), 20)
	}
	
    tl := &tokenLimiter{
        limiter:  new_rpm,
        lastUsed: now,
    }

    actual, _ := limiterMap.LoadOrStore(token, tl)
    return actual.(*tokenLimiter).limiter
}

func checkToken(authHeader, ipaddr string) bool {
    if authHeader == "" {
        return false
    }
    if !strings.HasPrefix(authHeader, "Bearer ") {
        return false
    }

    token := strings.TrimPrefix(authHeader, "Bearer ")

    _, ok := token_Map.Load(token)
    if !ok {
        logWarn.Println("ERR: Invalid token:", token, ",ip:", ipaddr)
        return false
    }

    limiter := getLimiter(token,false)
    if !limiter.Allow() {
        logWarn.Println("WARN: Rate limit exceeded token:", token, ",ip:", ipaddr)
        return false
    }

    logDebug.Println("INFO: recv Msg from token:", token, ",ip:", ipaddr)
    return true
}

func checkAndVeify_kep(msg []byte,token string){
	_,domain,_,_,_,perm,t_hash,tag,_,_,err:=kepresolv.Resolv(msg)
	if err !=nil {
		logWarn.Println("kepresolv err:",err)
		return
	}
	suffix, err := publicsuffix.EffectiveTLDPlusOne(string(domain))
	if err!=nil {
		suffix=string(domain)
	}
	deny_lock.RLock()
	_,ok:=deny_Map[suffix]
	deny_lock.RUnlock()
	if ok {
		logWarn.Println("drop deny user msg:",string(domain))
		return
	}
	
	limiter := getLimiter(suffix,true)
    if !limiter.Allow() {
        logWarn.Println("WARN: domain Rate limit exceeded:", suffix)
        return
    }
	
	logMust.Printf("INFO: access domain %s from token %s, msgTag=%d\n",suffix,token,tag)
	
	if tag == 65535 {
		//65535标签 是私信，不再转发下一跳
		if perm !=255 {
			//私信权限设置必须为255，否则丢弃
			logWarn.Println("INFO: drop private msg form",token)
			return
		}
	}
	
	err = verify.IngestMDB(msg);
	if err != nil {
		logErr.Println("resolv msg err:",err)
		return
	}
	if Skip_token != token {
		newMsg_logger.Store(hex.EncodeToString(t_hash),struct{}{})
	}
	
	if tag == 65535 {
		logDebug.Println("debug: get private msg form",token)
		if Skip_token != token {
		return
		}
	}
	
	logDebug.Println("debug: send msg to neighbor")
	err = send.Nextmsg(msg,token)
	if err != nil {
		logWarn.Println("send msg err:",err)
	}
}

func handleMsg(msgType string, body []byte,token string) ([]byte, error) {
    switch msgType {
    case "ping":
        return []byte("+PONG"), nil
    case "data":{
		go checkAndVeify_kep(body,token);
        return []byte("+OK"), nil
	}
    default:
        return nil, errors.New("unknown msg type: "+ msgType)
    }
}

func msgHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		io.WriteString(w,`{"error":{"message":"Invalid URL (GET /v1/messages)","type":"invalid_request_error","param":"","code":""}}`)
        return
    }

    r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
    defer r.Body.Close()

    auth := r.Header.Get("Authorization")
	user_ip := r.Header.Get("CF-Connecting-IP")
    if !checkToken(auth,user_ip) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }

    msgType := r.Header.Get("X-Msg-Type")
    if msgType == "" {
        http.Error(w, "missing X-Msg-Type", http.StatusBadRequest)
        return
    }

    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "read body failed", http.StatusBadRequest)
        return
    }
	token := strings.TrimPrefix(auth, "Bearer ")
    respMsg, err := handleMsg(msgType, body,token)
    if err != nil {
		logInfo.Println("Rrr msg",err.Error())
        http.Error(w, "Msg Error", http.StatusBadRequest)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write(respMsg)
}

func idxHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" && len(custom_pageidx)!=0 {
		w.Write(custom_pageidx)
		return
	}
	if len(custom_page404)!=0 {
		w.WriteHeader(404)
		w.Write(custom_page404)
		return
	}
	http.NotFound(w, r)
}

func main() {
	argc:=len(os.Args)
	if argc <=1 {
		logger.Print("usage:")
		logger.Print("\tkepserver [config.json] [logfile]")
		return
	}
	cfg_file:=os.Args[1]
	
	
	cfg,err := config.Resolv(cfg_file)
	if err!=nil {
		logger.Fatal("can't read config.json")
	}
	
	logger.SYS_Level(cfg.LogLevel)
	logDebug.SetLevel("debug")
	logInfo.SetLevel("info")
	logWarn.SetLevel("warn")
	logErr.SetLevel("err")
	logMust.SetLevel("must")
	
	if cfg.Listen == "" {
	logger.Fatal("Listen addr is null")
	}
	
	if len(cfg.ApiToken) < 8 {
		logger.Fatal("Err: apiToken is null")
	}
	g_token = cfg.ApiToken
	Skip_token = cfg.Skiptoken
	go verify.NewTTLMap()
	
	err = loadList(cfg.File_deny)
	if err!=nil {
		logErr.Println("load list err:",err)
	}
	err = loadToken(cfg.File_token,cfg.Socks5)
	if err!=nil {
		logErr.Println("load token err:",err)
	}
	if cfg.Apiport == "" {
		cfg.Apiport="10428"
	}
	if cfg.Ntp != "" {
		ntp.Ntp_Init(cfg.Ntp)
		logWarn.Println("start ntp client:",cfg.Ntp)
	}
	if cfg.Custom404 != "" {
		custom_page404, err = os.ReadFile(cfg.Custom404)
		if err != nil {
			logger.Fatalln("Err: can't read custom file404:",err)
		}
		logWarn.Println("init: set custom 404 page",cfg.Custom404)
	}
	if cfg.CustomIdx != "" {
		custom_pageidx, err = os.ReadFile(cfg.CustomIdx)
		if err != nil {
			logger.Fatalln("Err: can't read custom fileIdx:",err)
		}
		logWarn.Println("init: set custom index page",cfg.CustomIdx)
	}
{
	api := http.NewServeMux()
    api.HandleFunc("/local/api/interface", apiHandler)
	logWarn.Printf("api server listening 127.222.1.16:%s\n",cfg.Apiport)
    api_svc := &http.Server{
        Addr:         "127.222.1.16:"+cfg.Apiport,
        Handler:      api,
        ReadTimeout:  readTimeout,
        WriteTimeout: writeTimeout,
        IdleTimeout:  idleTimeout,
    }
	go func() {
        if err := api_svc.ListenAndServe(); err != nil {
            logger.Fatalf("api listen failed: %v", err)
        }
    }()
}
	
    mux := http.NewServeMux()
    mux.HandleFunc("/v1/messages", msgHandler)
	mux.HandleFunc("/", idxHandler)
	
    server := &http.Server{
        Addr:         cfg.Listen,
        Handler:      mux,
        ReadTimeout:  readTimeout,
        WriteTimeout: writeTimeout,
        IdleTimeout:  idleTimeout,
        TLSConfig: &tls.Config{
            MinVersion: tls.VersionTLS12,
        },
    }
	
	go startLimiterCleaner()
	go saveTask(cfg.File_deny,cfg.File_token);
	
	if argc >2 {
	logfile:=os.Args[2]
	logpath,err :=os.OpenFile(logfile,os.O_WRONLY|os.O_CREATE|os.O_APPEND,0644)
	if err != nil {
		logErr.Println(err)
		return
	}
	logger.SetOutput(logpath)
	}

    go func() {
	  if cfg.Crt !="" && cfg.Key !=""{
		logWarn.Printf("HTTPS server listen on %s\n", cfg.Listen)
        if err := server.ListenAndServeTLS(cfg.Crt,cfg.Key); err != nil && err != http.ErrServerClosed {
            logger.Fatalf("listen failed: %v", err)
		}
	  } else {
		logWarn.Printf("HTTP server listen on %s\n", cfg.Listen)
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            logger.Fatalf("listen failed: %v", err)
		}
	  }
    }()

    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    logMust.Println("shutting down server...")

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    if err := server.Shutdown(ctx); err != nil {
        logger.Fatalf("server shutdown failed: %v", err)
    }

    logMust.Println("server exited")
}


func apiHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	token := query.Get("token")
	if g_token != token {
		w.WriteHeader(403)
        w.Write([]byte("api token err"))
		return
	}
	svc := query.Get("svc")
	req := query.Get("req")
	if req == "" || svc == "" {
		w.Write([]byte("svc not found"))
		return
	}
	
switch svc {
case "msg":{
	//获取最近消息
	var buf bytes.Buffer
	first:=false
	buf.WriteString("[")
	will_del := make([]string,0,32)
	newMsg_logger.Range(func(key, value interface{}) bool {
            hash := key.(string)
			if first {buf.WriteString(",");}else{first=true;}
			buf.WriteString(`"`)
			buf.WriteString(hash)
			buf.WriteString(`"`)
			will_del=append(will_del,hash)
            return true
        })
	for _,hash := range will_del {
		newMsg_logger.Delete(hash)
	}
	buf.WriteString("]")
	w.Header().Set("Content-Type", "application/json")
    w.Write(buf.Bytes())
}
case "ban":{
	suffix, err := publicsuffix.EffectiveTLDPlusOne(req)
	if err!=nil {
		suffix=req
	}
    deny_lock.Lock()
	deny_Map[suffix]=true
	deny_lock.Unlock()
	w.Write([]byte("OK"))
}
case "unban":{
	suffix, err := publicsuffix.EffectiveTLDPlusOne(req)
	if err!=nil {
		suffix=req
	}
    deny_lock.Lock()
	_,ok:=deny_Map[suffix]
	if ok {delete(deny_Map,suffix);}
	deny_lock.Unlock()
	w.Write([]byte("OK"))
}
case "neighbor":{
	key := query.Get("key")
	if len(key)<8{
		w.Write([]byte("key<8"))
		return
	}
	url := query.Get("url")
	if req=="set"{
		rpm := query.Get("rpm")
		rpm_num,err:=strconv.Atoi(rpm)
		if err!=nil{
			rpm_num=30
		}
		if rpm_num <=0 {
			rpm_num=10
		}
		New_Ner:=&config.Neighbor{
			URL: url,
			Token: key,
			RPM: rpm_num,
		}
		token_Map.Store(key, New_Ner)
		send.Append(New_Ner.URL,New_Ner.Token)
	} else if req=="del"{
		token_Map.Delete(key)
		send.Remove(key)
	} else if req=="list"{

    list := make([]string,0,32)

    token_Map.Range(func(k, v interface{}) bool {
        if ka, ok := k.(string); ok {
            list = append(list, ka)
        }
        return true
    })

    resp := struct{
        State string   `json:"state"`
        Data  []string `json:"data"`
    }{
        State:"OK",
        Data:list,
    }

    w.Header().Set("Content-Type","application/json")
    json.NewEncoder(w).Encode(resp)
    return
}
	w.Write([]byte("OK"))
}
default:{
    w.Write([]byte("svc not found"))
}
}
}

func saveToken(filename string) error {
    tmp := make(map[string]config.Neighbor)
    token_Map.Range(func(k, v interface{}) bool {
        key, ok := k.(string)
        if ok {
			cfg:= v.(*config.Neighbor)
			if cfg.Token != "" {
				tmp[key] = *cfg
			}
        }
        return true
    })
    data, err := json.Marshal(tmp)
    if err != nil {
        return err
    }
    return os.WriteFile(filename, data, 0644)
}

func loadToken(filename,next_spcks5 string) error {
    data, err := os.ReadFile(filename)
    if err != nil {
        return err
    }
    tmp := make(map[string]config.Neighbor)
    if err := json.Unmarshal(data, &tmp); err != nil {
        return err
    }
	{
		Ner :=&config.Neighbor{}
		token_Map.Store(Skip_token, Ner)
	}
	nextroute=make([]send.NextMsg,len(tmp))
	i:=0
    for k,v := range tmp {
		val:=v
		nextroute[i].Addr=val.URL
		nextroute[i].Auth=val.Token
        token_Map.Store(k, &val)
		i++
    }
	send.Send_Init(nextroute,next_spcks5)
    return nil
}

func loadList(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    decoder := json.NewDecoder(file)
    err = decoder.Decode(&deny_Map)
    if err != nil {
        return err
    }
	return nil
}

func saveList(filename string) error {
    file, err := os.Create(filename)
    if err != nil {
		return err
    }
    encoder := json.NewEncoder(file)
	deny_lock.RLock()
    err = encoder.Encode(deny_Map)
	deny_lock.RUnlock()
	file.Close()
    if err != nil {
        return err
    }
	return nil
}

func saveTask(deny_file,token_file string){
for{
	time.Sleep(time.Second * 1200)
	err := saveList(deny_file);
	if err != nil {
        logWarn.Println("save err:",err);
    }
	err = saveToken(token_file);
	if err != nil {
        logWarn.Println("save err:",err);
    }
}
}