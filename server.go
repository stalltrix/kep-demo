package main

import (
    "context"
    "crypto/tls"
    "io"
    "log"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "syscall"
	"errors"
	"sync"
	"kep/verify"
	"kep/send"
	"kep/kepresolv"
	"time"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
	"kep/config"
	"encoding/hex"
	"bytes"
	"encoding/json"
)

type tokenLimiter struct {
    limiter   *rate.Limiter
    lastUsed  int64
}

var (
    maxBodySize  = int64(1 << 17) // 128K
    readTimeout  = 5 * time.Second
    writeTimeout = 5 * time.Second
    idleTimeout  = 60 * time.Second
	token_Map sync.Map
	nextroute []send.NextMsg
	deny_Map map[string]bool
	deny_lock sync.RWMutex
	limiterMap sync.Map
	g_token string
	newMsg_logger sync.Map
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

func getLimiter(token string) *rate.Limiter {
    now := time.Now().Unix()

    if v, ok := limiterMap.Load(token); ok {
        tl := v.(*tokenLimiter)
        tl.lastUsed = now
        return tl.limiter
    }

    tl := &tokenLimiter{
        limiter:  rate.NewLimiter(rate.Every(time.Minute/30), 30),
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
        log.Println("ERR: Invalid token:", token, ",ip:", ipaddr)
        return false
    }

    limiter := getLimiter(token)
    if !limiter.Allow() {
        log.Println("WARN: Rate limit exceeded token:", token, ",ip:", ipaddr)
        return false
    }

    return true
}

func checkAndVeify_kep(msg []byte,token string){
	_,domain,_,_,_,_,t_hash,_,err:=kepresolv.Resolv(msg)
	if err !=nil {
		log.Println("kepresolv err:",err)
		return
	}
	suffix, ok := publicsuffix.PublicSuffix(string(domain))
	if !ok {
		suffix=string(domain)
	}
	deny_lock.RLock()
	_,ok=deny_Map[suffix]
	deny_lock.RUnlock()
	if ok {
		log.Println("drop deny user msg:",string(domain))
		return
	}
	log.Println("INFO: access domain %s from token %s",suffix,token)
	err = verify.IngestMDB(msg);
	if err != nil {
		log.Println("resolv msg err:",err)
		return
	}
	newMsg_logger.Store(hex.EncodeToString(t_hash),struct{}{})
	err = send.Nextmsg(msg)
	if err != nil {
		log.Println("send msg err:",err)
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
		log.Println("Rrr msg",err.Error())
        http.Error(w, "Msg Error", http.StatusBadRequest)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write(respMsg)
}

func main() {
	argc:=len(os.Args)
	if argc <=1 {
		log.Println("usage:")
		log.Println("\tkepserver [config.json] [logfile]")
		return
	}
	cfg_file:=os.Args[1]
	
	
	cfg,err := config.Resolv(cfg_file)
	if err!=nil {
		log.Fatal("can't read config.json")
	}
	
	if cfg.Listen == "" {
	log.Fatal("Listen addr is null")
	}
	
	if len(cfg.ApiToken) < 8 {
		log.Fatal("Err: apiToken is null")
	}
	g_token = cfg.ApiToken
	
	nextroute=make([]send.NextMsg,len(cfg.Neighbors))
	for i:= range nextroute {
		nextroute[i].Addr=cfg.Neighbors[i].URL
		nextroute[i].Auth=cfg.Neighbors[i].Token
	}
	
	send.Send_Init(nextroute)
	err = loadlist()
	if err!=nil {
		log.Println("load list err:",err)
	}
	
{
	api := http.NewServeMux()
    api.HandleFunc("/local/api/interface", apiHandler)
	log.Printf("api server listening 127.222.1.16:10428\n")
    api_svc := &http.Server{
        Addr:         "127.222.1.16:10428",
        Handler:      api,
        ReadTimeout:  readTimeout,
        WriteTimeout: writeTimeout,
        IdleTimeout:  idleTimeout,
    }
	go func() {
        if err := api_svc.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("api listen failed: %v", err)
        }
    }()
}
	
    mux := http.NewServeMux()
    mux.HandleFunc("/v1/messages", msgHandler)
	
	log.Printf("HTTPS server listen on %s\n", cfg.Listen)
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
	go savelist();
	
	if argc >2 {
	logfile:=os.Args[2]
	logpath,err :=os.OpenFile(logfile,os.O_WRONLY|os.O_CREATE|os.O_APPEND,0644)
	if err != nil {
		log.Println(err)
		return
	}
	log.SetOutput(logpath)
	}

    go func() {
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("listen failed: %v", err)
        }
    }()
	go verify.NewTTLMap()

    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Println("shutting down server...")

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    if err := server.Shutdown(ctx); err != nil {
        log.Fatalf("server shutdown failed: %v", err)
    }

    log.Println("server exited")
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
	var buf bytes.Buffer
	first:=false
	buf.WriteString("[")
	newMsg_logger.Range(func(key, value interface{}) bool {
            hash := key.(string)
			if first {buf.WriteString(",");}else{first=true;}
			buf.WriteString(`"`)
			buf.WriteString(hash)
			buf.WriteString(`"`)
            newMsg_logger.Delete(hash)
            return true
        })
	buf.WriteString("]")
	w.Header().Set("Content-Type", "application/json")
    w.Write(buf.Bytes())
}
case "ban":{
    deny_lock.Lock()
	deny_Map[req]=true
	deny_lock.Unlock()
	w.Write([]byte("OK"))
}
case "unban":{
    deny_lock.Lock()
	_,ok:=deny_Map[req]
	if ok {delete(deny_Map,req);}
	deny_lock.Unlock()
	w.Write([]byte("OK"))
}
default:{
    w.Write([]byte("svc not found"))
}
}
}

func loadlist() error {
    file, err := os.Open("deny.json")
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

func savelist() {
for{
	time.Sleep(time.Second * 1200)
    file, err := os.Create("deny.json")
    if err != nil {
		log.Println("save err:",err)
        continue;
    }
    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
	deny_lock.RLock()
    err = encoder.Encode(deny_Map)
	deny_lock.RUnlock()
	file.Close()
    if err != nil {
        log.Println("save err:",err)
    }
}
}
