package proxytunnel

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"encrypt-proxy/internal/ntlm"
)

// Dial establishes a TCP connection through an HTTP CONNECT proxy,
// handling Basic and NTLMv2 proxy authentication.
func Dial(dial func() (net.Conn, error), serverAddr string, proxyURL *url.URL) (net.Conn, error) {
	conn, err := dial()
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	br := bufio.NewReader(conn)

	resp, err := doConnect(conn, br, serverAddr, "")
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

	if proxyURL.User == nil {
		conn.Close()
		return nil, fmt.Errorf("proxy requires authentication but no credentials configured")
	}

	authHeader := resp.Header.Get("Proxy-Authenticate")
	scheme, _, _ := strings.Cut(strings.TrimSpace(authHeader), " ")

	switch strings.ToUpper(scheme) {
	case "NTLM":
		// NTLMv2: 同一TCP接続でネゴシエーションを継続する
		return ntlmHandshake(conn, br, serverAddr, proxyURL)
	case "BASIC":
		// Basic: 407後にプロキシが接続を切る場合があるため再接続する
		conn.Close()
		conn, err = dial()
		if err != nil {
			return nil, fmt.Errorf("dial proxy for auth retry: %w", err)
		}
		br = bufio.NewReader(conn)
		user := proxyURL.User.Username()
		pass, _ := proxyURL.User.Password()
		resp, err = doConnect(conn, br, serverAddr, basicAuth(user, pass))
		if err != nil {
			conn.Close()
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("proxy CONNECT failed after auth: %s", resp.Status)
		}
		return conn, nil
	default:
		conn.Close()
		return nil, fmt.Errorf("proxy requires unsupported auth method: %s", authHeader)
	}
}

// ntlmHandshake performs the NTLMv2 3-way handshake (Negotiate→Challenge→Authenticate).
func ntlmHandshake(conn net.Conn, br *bufio.Reader, serverAddr string, proxyURL *url.URL) (net.Conn, error) {
	user := proxyURL.User.Username()
	pass, _ := proxyURL.User.Password()

	// Step 1: Negotiate
	negotiateMsg := ntlm.NewNegotiateMessage()
	resp, err := doConnect(conn, br, serverAddr, "NTLM "+base64.StdEncoding.EncodeToString(negotiateMsg))
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		conn.Close()
		return nil, fmt.Errorf("ntlm: expected 407 for challenge, got %s", resp.Status)
	}

	// Step 2: Parse Challenge
	challengeHeader := resp.Header.Get("Proxy-Authenticate")
	_, challengeB64, _ := strings.Cut(strings.TrimSpace(challengeHeader), " ")
	challengeBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(challengeB64))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ntlm: decode challenge: %w", err)
	}

	// Step 3: Authenticate
	authenticateMsg, err := ntlm.ProcessChallenge(challengeBytes, user, pass)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ntlm authenticate: %w", err)
	}
	resp, err = doConnect(conn, br, serverAddr, "NTLM "+base64.StdEncoding.EncodeToString(authenticateMsg))
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed after NTLM auth: %s", resp.Status)
	}
	return conn, nil
}

func doConnect(conn net.Conn, br *bufio.Reader, serverAddr, proxyAuth string) (*http.Response, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: serverAddr},
		Host:   serverAddr,
		Header: make(http.Header),
	}
	if proxyAuth != "" {
		req.Header.Set("Proxy-Authorization", proxyAuth)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	resp.Body.Close()
	return resp, nil
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}
