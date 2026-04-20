package relay

import (
	"bufio"
	"log/slog"
	"net/http"
	"time"

	"encrypt-proxy/internal/config"
	"encrypt-proxy/internal/iobridge"
	"encrypt-proxy/internal/tunnel"

	"github.com/xtaci/smux"
)

// handleWebSocket は WebSocket アップグレードを中継し、その後の双方向通信をブリッジする。
//
// WebSocket は HTTP/1.1 の Upgrade ハンドシェイクで始まり、成功後は
// HTTP のリクエスト/レスポンスモデルを離れて生のバイトストリームになる。
// そのため HTTP ループ処理の handleHTTP とは別に実装している。
func handleWebSocket(stream *smux.Stream, hdr tunnel.StreamHeader, cfg *config.ServerConfig, dialTimeout time.Duration) {
	streamReader := bufio.NewReaderSize(stream, 64*1024)

	// クライアントから Upgrade リクエスト（GET + Connection: Upgrade）を読む。
	req, err := http.ReadRequest(streamReader)
	if err != nil {
		slog.Error("ws: read upgrade request", "err", err)
		return
	}

	// Upgrade リクエストを受け取ってから宛先へ接続する。
	// dialUpstream より先に ReadRequest するのは、不正リクエストで無駄な接続を防ぐため。
	upstream, err := dialUpstream(hdr, cfg, dialTimeout)
	if err != nil {
		slog.Warn("ws: dial upstream", "target", hdr.HostPort, "err", err)
		writeErrorResponse(stream, http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	// http.ReadRequest は RequestURI を生のパスとして読むため、upstream への転送前にクリアする。
	req.RequestURI = ""

	if err := req.Write(upstream); err != nil {
		slog.Error("ws: write upgrade request to upstream", "err", err)
		return
	}

	upstreamReader := bufio.NewReaderSize(upstream, 64*1024)
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		slog.Error("ws: read upgrade response", "err", err)
		return
	}

	// 101 Switching Protocols をクライアントへ転送してアップグレード完了を伝える。
	if err := resp.Write(stream); err != nil {
		slog.Error("ws: write upgrade response to stream", "err", err)
		resp.Body.Close()
		return
	}
	resp.Body.Close()

	// upstream が 101 以外を返した場合はアップグレード失敗。
	// ストリームを閉じてクライアントにエラーレスポンスが届いた状態で終了する。
	if resp.StatusCode != http.StatusSwitchingProtocols {
		slog.Warn("ws: upstream did not upgrade", "status", resp.StatusCode)
		return
	}

	// アップグレード後は HTTP フレームではなく生バイトストリームになるため、
	// 両方向を goroutine で同時コピーする。どちらかが EOF/エラーになると
	// 両 goroutine が終了するまで待ってからストリームを閉じる。
	iobridge.Bridge(stream, upstream)
}
