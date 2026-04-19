# encrypt-proxy

## セットアップ手順

### 1. ビルド

```sh
go build -o server ./cmd/server
go build -o client ./cmd/client
go build -o keygen ./cmd/keygen
```

### 2. 鍵ペアを生成

鍵の生成は `keygen` コマンドで行う。起動時の自動生成はしないため、事前に必ず生成すること。

```sh
# サーバー用
./keygen -out ./data/server
# → data/server.key（秘密鍵）と data/server.pub（公開鍵）が生成される
# → data/server.pub の内容をクライアントに配布する

# クライアント用
./keygen -out ./data/client
# → data/client.key と data/client.pub が生成される
# → data/client.pub の内容をサーバーの authorized_keys に追記する
```

### 3. サーバーのauthorized_keysを作成

接続を許可するクライアントの公開鍵を1行1キーで列挙する。

```
# data/authorized_keys
9SYp00KCvgyQiEoJ4RhDmZZM81NW0YxHBkwJQCB56Cs=
```

### 4. 設定ファイルを編集

**サーバー（config/server.yaml）**

```yaml
listen_addr: "0.0.0.0:9443"
log_level: "info"
allowed_hosts: []

keys:
  server_key: "./data/server.key"
  authorized_keys: "./data/authorized_keys"

tls:
  cert: ""
  key: ""

timeouts:
  dial_ms: 10000
  response_ms: 60000
```

**クライアント（config/client.yaml）**

```yaml
listen_addr: "127.0.0.1:8080"
log_level: "info"

tunnel:
  server_addr: "your-server.example.com:9443"
  client_key: "./data/client.key"
  server_pub_key: "./data/server.pub"
  reconnect_delay_ms: 1000
  max_reconnect_delay_ms: 30000
  tls:
    ca_cert: ""
    insecure: false

mitm:
  ca_cert: "./data/ca.crt"
  ca_key: "./data/ca.key"
  leaf_cert_db: "./data/leaf_certs.db"

upstream_proxy:
  http_url: ""
  https_url: ""
  ca_cert: ""
  insecure: false
```

### 5. 起動

```sh
# サーバー側
./server --config config/server.yaml

# クライアント側
./client --config config/client.yaml
```

---

## 上流プロキシ経由の接続

```yaml
# クライアント側
upstream_proxy:
  http_url: "http://proxy.example.com:8080"
  https_url: "http://proxy.example.com:8080"
  # 認証が必要な場合は URL に認証情報を含める
  # http_url: "http://user:pass@proxy.example.com:8080"
  # プロキシ自体がHTTPSの場合はca_certでカスタムCAを指定
  ca_cert: ""
  insecure: false
```

## テスト

```sh
make test
```
