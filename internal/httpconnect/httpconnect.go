package httpconnect

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ConnectViaProxy は HTTP CONNECT ハンドシェイクを行い、407 の場合は Basic 認証で再試行する。
// 407 後にプロキシが接続を切る場合があるため、再試行時は dial で再接続する。
func ConnectViaProxy(dial func() (net.Conn, error), serverAddr string, proxyURL *url.URL) (net.Conn, error) {
	conn, err := dial()
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}

	resp, err := SendConnect(conn, serverAddr, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return conn, nil
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	// 407: Basic 認証チャレンジに応答する
	if proxyURL.User == nil {
		conn.Close()
		return nil, fmt.Errorf("proxy requires authentication but no credentials configured")
	}
	authHeader := resp.Header.Get("Proxy-Authenticate")
	if !strings.HasPrefix(strings.TrimSpace(authHeader), "Basic") {
		conn.Close()
		return nil, fmt.Errorf("proxy requires unsupported auth method: %s", authHeader)
	}

	// 407 後にプロキシが接続を閉じている可能性があるため再接続する
	conn.Close()
	conn, err = dial()
	if err != nil {
		return nil, fmt.Errorf("dial proxy for auth retry: %w", err)
	}

	user := proxyURL.User.Username()
	pass, _ := proxyURL.User.Password()
	resp, err = SendConnect(conn, serverAddr, &[2]string{user, pass})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed after auth: %s", resp.Status)
	}
	return conn, nil
}

// SendConnect は CONNECT リクエストを送信してレスポンスを返す。
// creds が非 nil の場合は Basic 認証ヘッダーを付与する。
func SendConnect(conn net.Conn, serverAddr string, creds *[2]string) (*http.Response, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: serverAddr},
		Host:   serverAddr,
		Header: make(http.Header),
	}
	if creds != nil {
		req.SetBasicAuth(creds[0], creds[1])
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	resp.Body.Close()
	return resp, nil
}
