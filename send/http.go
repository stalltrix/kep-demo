package send

import (
    "bytes"
    "crypto/tls"
    "fmt"
    "io"
    "net/http"
    "time"
	"golang.org/x/net/proxy"
)

var (
    requestTimeout = 5 * time.Second
	transport *http.Transport
	proxyAddr,socks_user,socks_pass string
)

type MsgClient struct {
    url        string
    authToken string
    httpCli   *http.Client
}

func NewMsgClient(url, token string) (*MsgClient,error) {
	transport = &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout:     90 * time.Second,
        TLSClientConfig: &tls.Config{
        MinVersion: tls.VersionTLS13,
        CurvePreferences: []tls.CurveID{
            tls.X25519,
            tls.CurveP256,
        },
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
		transport.Dial=dialer.Dial
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

    resp, err := c.httpCli.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf(
            "server error: status=%d body=%s",
            resp.StatusCode,
            string(body),
        )
    }

    respMsg, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    return respMsg, nil
}

func (c *MsgClient) Close() {
    if tr, ok := c.httpCli.Transport.(*http.Transport); ok {
        tr.CloseIdleConnections()
    }
}