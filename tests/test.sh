#!/bin/sh
set -e

PROXY="http://proxy-client:8080"
HTTPBIN="http://httpbin:8080"
CACERT="/certs/ca.crt"
WS_MESSAGE="hello-encrypt-proxy"
PASS=0
FAIL=0

green() { printf '\033[32m[PASS]\033[0m %s\n' "$1"; }
red()   { printf '\033[31m[FAIL]\033[0m %s\n' "$1"; }

check() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    green "$label"
    PASS=$((PASS + 1))
  else
    red "$label"
    FAIL=$((FAIL + 1))
  fi
}

# ── 起動待機 ────────────────────────────────────────────────
echo "==> CA証明書の生成を待機中..."
for i in $(seq 1 30); do
  [ -f "$CACERT" ] && break
  sleep 1
done
[ -f "$CACERT" ] || { echo "タイムアウト: ca.crt が見つかりません"; exit 1; }

echo "==> プロキシポート 8080 の起動を待機中..."
for i in $(seq 1 30); do
  nc -z proxy-client 8080 2>/dev/null && break
  sleep 1
done
nc -z proxy-client 8080 || { echo "タイムアウト: proxy-client:8080 に接続できません"; exit 1; }

echo ""
echo "======================================"
echo "  encrypt-proxy 動作テスト"
echo "======================================"
echo ""

# ── HTTP テスト ────────────────────────────────────────────
echo "--- HTTP (httpbin) ---"

check "GET $HTTPBIN/get" \
  curl -sf --max-time 15 --proxy "$PROXY" \
       "$HTTPBIN/get"

check "POST $HTTPBIN/post (JSON body)" \
  curl -sf --max-time 15 --proxy "$PROXY" \
       -X POST -H "Content-Type: application/json" -d '{"test":1}' \
       "$HTTPBIN/post"

check "レスポンスヘッダー Content-Type: application/json" \
  sh -c 'curl -si --max-time 15 --proxy "$1" "$2/get" | grep -qi "content-type: application/json"' \
  -- "$PROXY" "$HTTPBIN"

check "リダイレクト追従 $HTTPBIN/redirect/2" \
  curl -sf --max-time 15 --proxy "$PROXY" -L \
       "$HTTPBIN/redirect/2"

# ── HTTPS (MITM) テスト ────────────────────────────────────
# proxy-client が MITM で TLS を終端し、ca.crt で署名した証明書をテスターへ提示する。
# proxy-server 側は upstream_tls.insecure: true で httpbin-tls の自己署名証明書を許容。
echo ""
echo "--- HTTPS MITM (httpbin-tls) ---"

HTTPBIN_S="https://httpbin-tls"

check "GET $HTTPBIN_S/get" \
  curl -sf --max-time 15 --proxy "$PROXY" --cacert "$CACERT" \
       "$HTTPBIN_S/get"

check "POST $HTTPBIN_S/post" \
  curl -sf --max-time 15 --proxy "$PROXY" --cacert "$CACERT" \
       -X POST -H "Content-Type: application/json" -d '{"secure":true}' \
       "$HTTPBIN_S/post"

check "カスタムヘッダーの透過 $HTTPBIN_S/headers" \
  sh -c 'curl -sf --max-time 15 --proxy "$1" --cacert "$2" \
              -H "X-Test-Header: encrypt-proxy" \
              "$3/headers" | grep -q "X-Test-Header"' \
  -- "$PROXY" "$CACERT" "$HTTPBIN_S"

# ── SSE / Streaming テスト ─────────────────────────────────
echo ""
echo "--- SSE / Streaming (httpbin) ---"

check "GET $HTTPBIN/stream/3 (チャンク転送ストリーミング)" \
  sh -c 'curl -sf --max-time 15 --proxy "$1" "$2/stream/3" | wc -l | grep -qE "^[[:space:]]*3$"' \
  -- "$PROXY" "$HTTPBIN"

# ── WebSocket テスト ───────────────────────────────────────
echo ""
echo "--- WebSocket (ws-echo via CONNECT tunnel) ---"

check "ws://ws-echo:8765/ WebSocket 接続確認" \
  sh -c 'result=$(echo "hello" | websocat -1 --text \
       --ws-c-uri ws://ws-echo:8765/ \
       - "ws-c:cmd:socat - PROXY:proxy-client:ws-echo:8765,proxyport=8080" \
       2>/dev/null); \
       [ -n "$result" ]'

# ── 上流プロキシ経由テスト ─────────────────────────────────
echo ""
echo "==> 上流プロキシ経由クライアント ポート 8081 の起動を待機中..."
for i in $(seq 1 40); do
  curl -sf --max-time 3 --proxy "http://proxy-client-via-proxy:8081" \
       "$HTTPBIN/get" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf --max-time 3 --proxy "http://proxy-client-via-proxy:8081" \
     "$HTTPBIN/get" >/dev/null 2>&1 || { echo "タイムアウト: proxy-client-via-proxy:8081 に接続できません"; exit 1; }
# upstream-proxy 再起動後、smux セッション再確立まで WS 接続が安定するまで待機
sleep 3

echo ""
echo "--- 上流プロキシ経由 (proxy-client-via-proxy → mitmproxy → proxy-server) ---"

PROXY_VIA="http://proxy-client-via-proxy:8081"

check "GET $HTTPBIN/get (via upstream proxy)" \
  curl -sf --max-time 15 --proxy "$PROXY_VIA" \
       "$HTTPBIN/get"

check "POST $HTTPBIN/post (via upstream proxy)" \
  curl -sf --max-time 15 --proxy "$PROXY_VIA" \
       -X POST -H "Content-Type: application/json" -d '{"via":"upstream-proxy"}' \
       "$HTTPBIN/post"

check "レスポンスヘッダー Content-Type (via upstream proxy)" \
  sh -c 'curl -si --max-time 15 --proxy "$1" "$2/get" | grep -qi "content-type: application/json"' \
  -- "$PROXY_VIA" "$HTTPBIN"

check "リダイレクト追従 $HTTPBIN/redirect/2 (via upstream proxy)" \
  curl -sf --max-time 15 --proxy "$PROXY_VIA" -L \
       "$HTTPBIN/redirect/2"

check "GET $HTTPBIN_S/get (via upstream proxy)" \
  curl -sf --max-time 15 --proxy "$PROXY_VIA" --cacert "$CACERT" \
       "$HTTPBIN_S/get"

check "POST $HTTPBIN_S/post (via upstream proxy)" \
  curl -sf --max-time 15 --proxy "$PROXY_VIA" --cacert "$CACERT" \
       -X POST -H "Content-Type: application/json" -d '{"via":"upstream-proxy","secure":true}' \
       "$HTTPBIN_S/post"

check "カスタムヘッダーの透過 $HTTPBIN_S/headers (via upstream proxy)" \
  sh -c 'curl -sf --max-time 15 --proxy "$1" --cacert "$2" \
              -H "X-Test-Header: encrypt-proxy-via" \
              "$3/headers" | grep -q "X-Test-Header"' \
  -- "$PROXY_VIA" "$CACERT" "$HTTPBIN_S"

check "SSE ストリーミング $HTTPBIN/stream/3 (via upstream proxy)" \
  sh -c 'curl -sf --max-time 15 --proxy "$1" "$2/stream/3" | wc -l | grep -qE "^[[:space:]]*3$"' \
  -- "$PROXY_VIA" "$HTTPBIN"

check "WebSocket 接続確認 ws://ws-echo:8765/ (via upstream proxy)" \
  sh -c 'result=$(echo "hello" | websocat -1 --text \
       --ws-c-uri ws://ws-echo:8765/ \
       - "ws-c:cmd:socat - PROXY:proxy-client-via-proxy:ws-echo:8765,proxyport=8081" \
       2>/dev/null); \
       [ -n "$result" ]'

# ── 結果サマリー ───────────────────────────────────────────
echo ""
echo "======================================"
printf "  結果: \033[32m%d PASS\033[0m / \033[31m%d FAIL\033[0m\n" "$PASS" "$FAIL"
echo "======================================"

[ "$FAIL" -eq 0 ]
