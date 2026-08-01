package send

import (
    "bytes"
    "crypto/tls"
    "io"
    "net/http"
    "time"
	"golang.org/x/net/proxy"
	"sync"
	"errors"
	"context"
	"net"
)

var (
    requestTimeout = 10 * time.Second
	proxyAddr,socks_user,socks_pass string
	transport_Cache sync.Map
)

type MsgClient struct {
    url        string
    authToken string
	UserAgent string
	Headers map[string]string
    httpCli   *http.Client
}

func NewMsgClient(url, token string,skipSSLchk bool) (*MsgClient,error) {
	var transport *http.Transport
if val, ok := transport_Cache.Load(url); ok {
    transport = val.(*http.Transport)
} else {
    newTr := &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 20,
        IdleConnTimeout:     90 * time.Second,
        TLSClientConfig: &tls.Config{
            MinVersion: tls.VersionTLS12,
            CurvePreferences: []tls.CurveID{
                tls.X25519,
                tls.CurveP256,
            },
			InsecureSkipVerify: skipSSLchk,
        },
    }
	if proxyAddr != "" {
		var auth *proxy.Auth
		if len(socks_user) !=0 && len(socks_pass) !=0 {
			auth = &proxy.Auth{
			User:     socks_user,
			Password: socks_pass,
			}
		}
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
		if err != nil {
			return nil,err
		}
		newTr.Dial=dialer.Dial
	}
	val, _ := transport_Cache.LoadOrStore(url, newTr)
    transport = val.(*http.Transport)
}

    return &MsgClient{
        url:        url,
        authToken: token,
        httpCli: &http.Client{
        Timeout:   requestTimeout,
        Transport: transport,
        },
    },nil
}

func (c *MsgClient) Send(msgType string, msg []byte) ([]byte, error) {
    req, err := http.NewRequest(
        http.MethodPost,
        c.url+"/v1/messages",
        bytes.NewReader(msg),
    )
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/octet-stream")
    req.Header.Set("Authorization", "Bearer "+c.authToken)
    req.Header.Set("X-Msg-Type", msgType)
	if c.UserAgent!=""{
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if len(c.Headers)>0 {
		for k, v := range c.Headers {
			req.Header.Set(k, v)
		}
	}

    resp, err := c.httpCli.Do(req)
    if err != nil {
		c.Close()
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        io.Copy(io.Discard, resp.Body)
        return nil, errors.New("server error: status not OK")
    }

    respMsg, err := io.ReadAll(io.LimitReader(resp.Body, 1 << 16))
    if err != nil {
	if errors.Is(err, context.DeadlineExceeded) {
        return respMsg, nil
    }
    if ne, ok := err.(net.Error); ok && ne.Timeout() {
        return respMsg, nil
    }
        return nil, err
    }
    return respMsg, nil
}

func (c *MsgClient) Close() {
val,ok:=transport_Cache.Load(c.url)
if ok {
	tr := val.(*http.Transport)
    tr.CloseIdleConnections()
	transport_Cache.Delete(c.url)
}
}