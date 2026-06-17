#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include "hmac.h"
#include "sha256.h"

#define VERSION "v0.2.0.beta"
#define BUFFER_SIZE 4096
#define DEFAULT_PORT 7000
#define DEFAULT_TOKEN "nexuslink123"

static void print_banner() {
    printf("========================================\n");
    printf("   NexusLink Client %s\n", VERSION);
    printf("   纯C语言自主引擎\n");
    printf("========================================\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    char *server_ip = "127.0.0.1";
    int server_port = DEFAULT_PORT;
    char *token = DEFAULT_TOKEN;
    
    // 解析参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            server_ip = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            server_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            token = argv[++i];
        }
    }

    print_banner();
    printf("📝 配置:\n");
    printf("   服务器: %s:%d\n", server_ip, server_port);
    printf("   Token: %s\n", token);
    printf("\n");

    // 创建socket连接服务端
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket failed");
        return 1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &addr.sin_addr);

    printf("🔌 连接服务器 %s:%d...\n", server_ip, server_port);
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect failed");
        close(sock);
        return 1;
    }

    printf("✅ 连接成功！\n");
    printf("🚀 NexusLink 客户端运行中...\n");
    printf("\n");

    // 简单的转发循环
    uint8_t buffer[BUFFER_SIZE];
    while (1) {
        int n = read(sock, buffer, BUFFER_SIZE);
        if (n <= 0) break;
        printf("📦 收到数据: %d 字节\n", n);
    }

    close(sock);
    printf("❌ 连接断开\n");
    return 0;
}
