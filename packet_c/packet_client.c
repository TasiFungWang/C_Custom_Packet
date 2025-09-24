#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

// 連線到 Relay
#define SERVER_IP   "127.0.0.1"
#define SERVER_PORT 7777

#define MAX_PAYLOAD 1024

// 協定常數
#define MAGIC1 0xAA
#define MAGIC2 0xBB

#define TYPE_DATA       0x01
#define TYPE_HEARTBEAT  0x02
#define TYPE_ACK        0xA0
#define TYPE_NACK_SD    0xA1

#define FLAG_REQUIRE_ACK        0x01
#define FLAG_SELF_DESTRUCT_EN   0x02
#define FLAG_COMPRESSED         0x04

// 封包內 priority 值
#define PRIO_DELAYED    0
#define PRIO_IMMEDIATE  1
#define PRIO_EPHEMERAL  2
#define PRIO_MEDIA      3

static unsigned char xor_checksum(const unsigned char* data, uint16_t len){
    unsigned char s = 0;
    for (uint16_t i=0; i<len; ++i) s ^= data[i];
    return s;
}

// 簡易 RLE 壓縮：AAABBB → [5 'A'][3 'B']
static int rle_compress(const unsigned char* in, int inlen, unsigned char* out, int outcap){
    int oi = 0;
    for (int i=0; i<inlen; ){
        unsigned char v = in[i];
        int cnt = 1;
        while (i+cnt < inlen && in[i+cnt]==v && cnt < 255) cnt++;
        if (oi + 2 > outcap) return -1;
        out[oi++] = (unsigned char)cnt;
        out[oi++] = v;
        i += cnt;
    }
    return oi;
}

static int send_packet(SOCKET s,
                       unsigned char type,
                       unsigned char priority,
                       unsigned char flags,
                       unsigned char ttl,
                       const unsigned char* payload,
                       uint16_t len)
{
    unsigned char pkt[8 + MAX_PAYLOAD + 1];
    if (len > MAX_PAYLOAD){ fprintf(stderr, "payload too large\n"); return -1; }

    pkt[0]=MAGIC1; pkt[1]=MAGIC2;
    pkt[2]=type;
    pkt[3]=priority;
    pkt[4]=flags;
    pkt[5]=ttl; // Relay 在路上遞減；若啟 SELF_DESTRUCT 且變 0 → 回 NACK
    pkt[6]=len & 0xFF; pkt[7]=(len>>8)&0xFF;
    memcpy(&pkt[8], payload, len);
    pkt[8+len] = xor_checksum(payload, len);

    int n = send(s, (const char*)pkt, 8 + len + 1, 0);
    if (n == SOCKET_ERROR){ fprintf(stderr, "send error\n"); return -1; }

    printf("已送出：type=0x%02X prio=%u flags=0x%02X ttl=%u len=%u\n",
           type, priority, flags, ttl, len);
    return 0;
}

// 等待 ACK/NACK（含 timeout）；回：0=ACK、1=NACK_SD、-1=timeout
static int wait_ack_or_nack(SOCKET s, int timeout_ms){
    fd_set rset; FD_ZERO(&rset); FD_SET(s, &rset);
    struct timeval tv; tv.tv_sec = timeout_ms/1000; tv.tv_usec = (timeout_ms%1000)*1000;
    int r = select((int)(s+1), &rset, NULL, NULL, &tv);
    if (r <= 0) return -1;

    unsigned char buf[8 + MAX_PAYLOAD + 1];
    int n = recv(s, (char*)buf, sizeof(buf), 0);
    if (n <= 0) return -1;

    if (n < 9 || buf[0]!=MAGIC1 || buf[1]!=MAGIC2) return -1;
    unsigned char type = buf[2];
    uint16_t L = (uint16_t)(buf[6] | (buf[7]<<8));
    if (8 + L + 1 != n) return -1;

    unsigned char* payload = &buf[8];
    if (xor_checksum(payload, L) != buf[8+L]) return -1;

    if (type == TYPE_ACK){
        printf("[Client] 收到 ACK：%.*s\n", L, (char*)payload);
        return 0;
    } else if (type == TYPE_NACK_SD){
        printf("[Client] 收到 NACK(SELF_DESTRUCTED)：%.*s\n", L, (char*)payload);
        return 1;
    } else {
        return -1;
    }
}

static void trim_newline(char* s){
    if (!s) return;
    size_t n = strlen(s);
    if (n && (s[n-1]=='\n' || s[n-1]=='\r')) s[n-1] = '\0';
}

int main(void){
    #ifdef _WIN32
    // 輸入/輸出都設定成 UTF-8 (這樣才能輸出中文，不然都是亂碼)
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0){ fprintf(stderr, "WSAStartup failed\n"); return 1; }

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET){ fprintf(stderr, "socket failed\n"); return 1; }

    struct sockaddr_in svr;
    svr.sin_family = AF_INET;
    svr.sin_port = htons(SERVER_PORT);
    svr.sin_addr.s_addr = inet_addr(SERVER_IP);
    if (connect(s, (struct sockaddr*)&svr, sizeof(svr)) == SOCKET_ERROR){
        fprintf(stderr, "connect failed to %s:%d\n", SERVER_IP, SERVER_PORT);
        return 1;
    }
    printf("Connected to relay %s:%d\n\n", SERVER_IP, SERVER_PORT);

    printf("=== 功能選單 ===\n");
    printf("0) 延遲顯示（保存、不立即顯示）\n");
    printf("1) 即時顯示（回 ACK）\n");
    printf("2) 輕量/短暫（顯示後即忘，回 ACK）\n");
    printf("3) 多媒體/壓縮（RLE 壓縮，server 自動解壓，回 ACK）\n");
    printf("4) 自毀重傳 Demo（ttl=1 啟自毀 → Relay 回 NACK → 立即以 ttl=3 重傳）\n");
    printf("5) HEARTBEAT（回 ACK）\n");
    printf("q) 離開\n\n");

    char line[2048], msgbuf[1024];

    for (;;){
        printf("請輸入選項：");
        if (!fgets(line, sizeof(line), stdin)) break;
        trim_newline(line);
        if (line[0]=='q' || line[0]=='Q') break;

        switch (line[0]){
        case '0': { // P0 延遲顯示
            printf("輸入訊息（預設: \"Store only (P0)\"）:");
            if (!fgets(msgbuf, sizeof(msgbuf), stdin)) strcpy(msgbuf, "Store only (P0)\n");
            trim_newline(msgbuf);
            const char* use = (msgbuf[0]) ? msgbuf : "Store only (P0)";
            send_packet(s, TYPE_DATA, PRIO_DELAYED, 0, 3,
                        (const unsigned char*)use, (uint16_t)strlen(use));
            break;
        }
        case '1': { // P1 即時顯示 + ACK
            printf("輸入訊息（預設: \"Hello (P1)\"）:");
            if (!fgets(msgbuf, sizeof(msgbuf), stdin)) strcpy(msgbuf, "Hello (P1)\n");
            trim_newline(msgbuf);
            const char* use = (msgbuf[0]) ? msgbuf : "Hello (P1)";
            send_packet(s, TYPE_DATA, PRIO_IMMEDIATE, FLAG_REQUIRE_ACK, 3,
                        (const unsigned char*)use, (uint16_t)strlen(use));
            int r = wait_ack_or_nack(s, 1500);
            if (r != 0) printf("未獲 ACK（ret=%d）\n", r);
            break;
        }
        case '2': { // P2 輕量/短暫 + ACK
            printf("輸入訊息（預設: \"Ephemeral (P2)\"）:");
            if (!fgets(msgbuf, sizeof(msgbuf), stdin)) strcpy(msgbuf, "Ephemeral (P5)\n");
            trim_newline(msgbuf);
            const char* use = (msgbuf[0]) ? msgbuf : "Ephemeral (P5)";
            send_packet(s, TYPE_DATA, PRIO_EPHEMERAL, FLAG_REQUIRE_ACK, 3,
                        (const unsigned char*)use, (uint16_t)strlen(use));
            int r = wait_ack_or_nack(s, 1500);
            if (r != 0) printf("未獲 ACK（ret=%d）\n", r);
            break;
        }
        case '3': { // P3 多媒體/壓縮 + ACK
            printf("輸入原始字串（預設: \"AAAAABBBCCCCCCCCDD\"）:");
            if (!fgets(msgbuf, sizeof(msgbuf), stdin)) strcpy(msgbuf, "AAAAABBBCCCCCCCCDD\n");
            trim_newline(msgbuf);
            const char* use = (msgbuf[0]) ? msgbuf : "AAAAABBBCCCCCCCCDD";

            unsigned char comp[MAX_PAYLOAD];
            int clen = rle_compress((const unsigned char*)use, (int)strlen(use), comp, MAX_PAYLOAD);
            if (clen < 0){ printf("RLE 壓縮失敗\n"); break; }

            printf("[Client] 壓縮前長度=%d, 壓縮後長度=%d\n", (int)strlen(use), clen);
            printf("[Client] 原始內容: \"%s\"\n", use);
            printf("[Client] 壓縮後資料 (hex): ");
            for (int i = 0; i < clen; ++i) printf("%02X ", comp[i]);
            printf("\n");

            send_packet(s, TYPE_DATA, PRIO_MEDIA, FLAG_REQUIRE_ACK | FLAG_COMPRESSED, 3,
                        comp, (uint16_t)clen);
            int r = wait_ack_or_nack(s, 1500);
            if (r != 0) printf("未獲 ACK（ret=%d）\n", r);
            break;
        }
        case '4': { // 自毀重傳 Demo (測試用)
            const char* msg = "Self-destruct demo";
            unsigned retries = 0, maxr = 3;

            // 先故意設定 ttl=1（Relay 遞減→0→NACK）
            send_packet(s, TYPE_DATA, PRIO_IMMEDIATE, FLAG_REQUIRE_ACK | FLAG_SELF_DESTRUCT_EN, 1,
                        (const unsigned char*)msg, (uint16_t)strlen(msg));

            for (;;){
                int ret = wait_ack_or_nack(s, 1200);
                if (ret == 0){ printf("[Client] 完成（已獲 ACK）\n"); break; }
                else if (ret == 1){
                    if (++retries > maxr){ printf("[Client] 重試超上限\n"); break; }
                    printf("[Client] 收到 NACK → 立即重傳（ttl=3）\n");
                    send_packet(s, TYPE_DATA, PRIO_IMMEDIATE, FLAG_REQUIRE_ACK | FLAG_SELF_DESTRUCT_EN, 3,
                                (const unsigned char*)msg, (uint16_t)strlen(msg));
                } else {
                    if (++retries > maxr){ printf("[Client] timeout 重試超上限\n"); break; }
                    printf("[Client] timeout → 重傳（ttl=3）\n");
                    send_packet(s, TYPE_DATA, PRIO_IMMEDIATE, FLAG_REQUIRE_ACK | FLAG_SELF_DESTRUCT_EN, 3,
                                (const unsigned char*)msg, (uint16_t)strlen(msg));
                }
            }
            break;
        }
        case '5': { // 確認對方是否存在
            const char* hb = "HEARTBEAT";
            send_packet(s, TYPE_HEARTBEAT, PRIO_IMMEDIATE, FLAG_REQUIRE_ACK, 3,
                        (const unsigned char*)hb, (uint16_t)strlen(hb));
            int r = wait_ack_or_nack(s, 1200);
            if (r != 0) printf("心跳未獲 ACK（ret=%d）\n", r);
            break;
        }
        default:
            printf("未知選項，請輸入 0/1/2/3/4/9 或 q\n");
        }
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
