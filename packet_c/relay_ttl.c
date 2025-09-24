#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

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

#define MAX_PAYLOAD 1024
#define MAX_PKT (8 + MAX_PAYLOAD + 1)

static int   g_listen_port = 7777;       // Relay 對 client 監聽
static char  g_up_ip[64]   = "127.0.0.1";// 上游 server IP
static int   g_up_port     = 8888;       // 上游 server Port
static int   g_delay_ms    = 0;          // 固定延遲（毫秒）
static float g_drop_prob   = 0.0f;       // 機率丟包（0.0~1.0）(但沒時間做相應機制，可以當不存在)
static int   g_verbose     = 1;

static unsigned char xor_checksum(const unsigned char* data, uint16_t len){
    unsigned char s = 0;
    for (uint16_t i=0; i<len; ++i) s ^= data[i];
    return s;
}
static void msleep(int ms){ if (ms > 0) Sleep(ms); }

static void parse_argv(int argc, char** argv){
    if (argc > 1) g_listen_port = atoi(argv[1]);
    if (argc > 2) strncpy(g_up_ip, argv[2], sizeof(g_up_ip)-1);
    if (argc > 3) g_up_port = atoi(argv[3]);
    if (argc > 4) g_delay_ms = atoi(argv[4]);
    if (argc > 5) g_drop_prob = (float)atof(argv[5]) / 100.0f;
}

// 回 NACK(SELF_DESTRUCTED) 告知 client 在路上自毀，讓 client 立刻重傳
static void send_nack_sd(SOCKET to_client, unsigned char ref_prio){
    const char* txt = "SELF_DESTRUCTED@RELAY";
    uint16_t L = (uint16_t)strlen(txt);
    unsigned char pkt[8 + 64 + 1];
    pkt[0]=MAGIC1; pkt[1]=MAGIC2;
    pkt[2]=TYPE_NACK_SD;
    pkt[3]=ref_prio;          // 帶 priority 便於除錯
    pkt[4]=0;
    pkt[5]=3;
    pkt[6]=L & 0xFF; pkt[7]=(L>>8)&0xFF;
    memcpy(&pkt[8], txt, L);
    pkt[8+L] = xor_checksum((unsigned char*)txt, L);
    send(to_client, (const char*)pkt, 8 + L + 1, 0);
}

// 原樣轉送（C->S 或 S->C）
static int forward_packet(SOCKET to, const unsigned char* buf, int n){
    int sent = send(to, (const char*)buf, n, 0);
    return (sent == SOCKET_ERROR) ? -1 : 0;
}

int main(int argc, char** argv){
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif

    parse_argv(argc, argv);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0){ fprintf(stderr, "WSAStartup failed\n"); return 1; }
    srand((unsigned)time(NULL));

    SOCKET listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == INVALID_SOCKET){ fprintf(stderr, "socket failed\n"); return 1; }

    struct sockaddr_in laddr; 
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = INADDR_ANY;
    laddr.sin_port = htons(g_listen_port);

    if (bind(listen_fd, (struct sockaddr*)&laddr, sizeof(laddr)) == SOCKET_ERROR){ fprintf(stderr, "bind failed\n"); return 1; }
    if (listen(listen_fd, 8) == SOCKET_ERROR){ fprintf(stderr, "listen failed\n"); return 1; }

    printf("Relay listen %d -> upstream %s:%d (delay=%dms drop=%.1f%%)\n",
           g_listen_port, g_up_ip, g_up_port, g_delay_ms, g_drop_prob*100.0f);

    for (;;){
        struct sockaddr_in caddr; int clen = sizeof(caddr);
        SOCKET cs = accept(listen_fd, (struct sockaddr*)&caddr, &clen);
        if (cs == INVALID_SOCKET) continue;
        printf("Client connected to relay.\n");

        SOCKET us = socket(AF_INET, SOCK_STREAM, 0);
        if (us == INVALID_SOCKET){ closesocket(cs); continue; }

        struct sockaddr_in saddr;
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(g_up_port);
        saddr.sin_addr.s_addr = inet_addr(g_up_ip);
        if (connect(us, (struct sockaddr*)&saddr, sizeof(saddr)) == SOCKET_ERROR){
            printf("Relay cannot connect upstream.\n");
            closesocket(us); closesocket(cs); continue;
        }
        printf("Relay connected to upstream.\n");

        for (;;){
            fd_set rset; FD_ZERO(&rset);
            FD_SET(cs, &rset);
            FD_SET(us, &rset);
            int maxfd = (int)((cs>us)?cs:us);

            int r = select(maxfd + 1, &rset, NULL, NULL, NULL);
            if (r == SOCKET_ERROR){ printf("select error\n"); break; }

            // client -> relay
            if (FD_ISSET(cs, &rset)){
                unsigned char buf[MAX_PKT];
                int n = recv(cs, (char*)buf, sizeof(buf), 0);
                if (n <= 0){ printf("client closed\n"); break; }

                // 解析自訂封包：至少 9 bytes；header 正確；長度匹配；checksum 正確
                if (n >= 9 && buf[0]==MAGIC1 && buf[1]==MAGIC2){
                    unsigned char type = buf[2];
                    unsigned char prio = buf[3];
                    unsigned char flags= buf[4];
                    unsigned char ttl  = buf[5];
                    uint16_t L = (uint16_t)(buf[6] | (buf[7]<<8));

                    if (8 + L + 1 == n && xor_checksum(&buf[8], L) == buf[8+L]){
                        if (g_verbose) printf("[Relay] C->R type=0x%02X prio=%u flags=0x%02X ttl=%u len=%u\n",
                                              type, prio, flags, ttl, L);
                        // 1) 在路上遞減 TTL
                        if (ttl > 0){ ttl -= 1; buf[5] = ttl; }

                        // 2) 在路上自毀：啟用 SELF_DESTRUCT 且 TTL 歸零
                        if ((flags & FLAG_SELF_DESTRUCT_EN) && ttl == 0){
                            printf("[Relay] SELF_DESTRUCT → drop & NACK to client\n");
                            send_nack_sd(cs, prio);
                            continue; // 不轉送 server
                        }

                        // 3) 壅塞模擬：延遲 + 機率丟包 (尚未做相應措施，可當不存在XD)
                        if (g_delay_ms > 0) msleep(g_delay_ms);
                        if (g_drop_prob > 0.0f){
                            float p = (float)rand() / (float)RAND_MAX;
                            if (p < g_drop_prob){
                                printf("[Relay] drop by probability\n");
                                continue; // 直接丟棄
                            }
                        }

                        // 4) 正常前送到 server
                        if (forward_packet(us, buf, n) < 0){ printf("forward upstream failed\n"); break; }
                        continue;
                    }
                }

                // 非自訂封包/驗證失敗 -> 原樣轉送
                if (forward_packet(us, buf, n) < 0){ printf("forward upstream failed\n"); break; }
            }

            // server -> relay -> client
            if (FD_ISSET(us, &rset)){
                unsigned char buf[MAX_PKT];
                int n = recv(us, (char*)buf, sizeof(buf), 0);
                if (n <= 0){ printf("upstream closed\n"); break; }

                if (g_verbose){
                    if (n >= 3 && buf[0]==MAGIC1 && buf[1]==MAGIC2)
                        printf("[Relay] U->R type=0x%02X → client\n", buf[2]);
                    else
                        printf("[Relay] U->R %d bytes passthrough\n", n);
                }
                if (forward_packet(cs, buf, n) < 0){ printf("forward client failed\n"); break; }
            }
        }

        closesocket(us);
        closesocket(cs);
        printf("Relay session closed.\n");
    }

    closesocket(listen_fd);
    WSACleanup();
    return 0;
}
