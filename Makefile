.PHONY: up down test logs build clean

DC = docker compose -f tests/compose.yml

# サービスをバックグラウンドで起動
up:
	$(DC) up -d --build proxy-server proxy-client ws-echo httpbin httpbin-tls

# テストスイートを実行 (結果をフォアグラウンドで表示)
test:
	$(DC) --profile test build
	$(DC) --profile test up -d proxy-server proxy-client ws-echo httpbin httpbin-tls
	$(DC) --profile test run --rm tester

# ログを表示 (Ctrl+C で停止)
logs:
	$(DC) logs -f proxy-server proxy-client

# 全サービスを停止
down:
	$(DC) down -v

# イメージだけビルド
build:
	$(DC) build

# コンテナ・イメージ・ボリュームを全削除
clean:
	$(DC) down -v --rmi local
