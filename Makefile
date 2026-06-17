CC = gcc
CFLAGS = -Wall -O2 -I./include -pthread

VERSION = 0.2.0.beta

all: server client

server:
	@echo "========================================"
	@echo "编译 NexusLink 服务端 v$(VERSION)"
	@echo "纯C语言自主引擎"
	@echo "========================================"
	$(CC) $(CFLAGS) -o nexuslink-server src/server.c src/hmac.c src/sha256.c
	@echo ""
	@echo "✅ 服务端编译完成"
	@ls -lh nexuslink-server
	@echo ""

client:
	@echo "========================================"
	@echo "编译 NexusLink 客户端 v$(VERSION)"
	@echo "纯C语言自主引擎"
	@echo "========================================"
	$(CC) $(CFLAGS) -o nexuslink-client src/client.c src/hmac.c src/sha256.c
	@echo ""
	@echo "✅ 客户端编译完成"
	@ls -lh nexuslink-client
	@echo ""

clean:
	rm -f nexuslink-server nexuslink-client
	@echo "🧹 清理完成"
