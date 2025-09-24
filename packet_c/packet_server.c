#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_PORT 8888
#define MAX_CLIENTS FD_SETSIZE
#define MAX_PAYLOAD 1024

// 協定常數
#define MAGIC1 0xAA
#define MAGIC2 0xBB

// type
#define TYPE_DATA       0x01
#define TYPE_HEARTBEAT  0x02
#define TYPE_ACK        0xA0

// flags
#define FLAG_REQUIRE_ACK        0x01
#define FLAG_SELF_DESTRUCT_EN   0x02 // 由 relay 處理
#define FLAG_COMPRESSED         0x04 // P3 壓縮

// priorities（應用層語義）
#define PRIO_DELAYED    0   // P0：延遲顯示
#define PRIO_IMMEDIATE  1   // P1：立即顯示
#define PRIO_EPHEMERAL  2   // P2：輕量/短暫
#define PRIO_MEDIA      3   // P3：允許壓縮，server 自動解壓

static unsigned char xor_checksum(const unsigned char* data, uint16_t len){
    unsigned char s = 0;
    for (uint16_t i = 0; i < len; ++i) s ^= data[i];
    return s;
}

static void print_hex(const unsigned char* buf, int n){
    for (int i = 0; i < n; ++i) printf("%02X ", buf[i]);
    printf("\n");
}

// 簡易 RLE 解壓：[count][value]
static int rle_decompress(const unsigned char* in, int inlen, unsigned char* out, int outcap){
    int oi = 0;
    for (int i = 0; i + 1 < inlen; i += 2){
        int cnt = in[i];
        unsigned char v = in[i+1];
        if (oi + cnt > outcap) return -1;
        for (int k = 0; k < cnt; ++k) out[oi++] = v;
    }
    return oi;
}

// 回 ACK（把原 priority 放進回封包的 priority 欄位便於除錯）
static void send_ack(SOCKET s, unsigned char ref_prio, const char* text){
    unsigned char pkt[8 + 64 + 1];
    const char* msg = (text && *text) ? text : "ACK";
    uint16_t L = (uint16_t)strlen(msg);
    pkt[0]=MAGIC1; pkt[1]=MAGIC2;
    pkt[2]=TYPE_ACK;
    pkt[3]=ref_prio;
    pkt[4]=0;      // flags
    pkt[5]=3;      // ttl（回覆用）
    pkt[6]=L & 0xFF; pkt[7]=(L>>8)&0xFF;
    memcpy(&pkt[8], msg, L);
    pkt[8+L] = xor_checksum((unsigned char*)msg, L);
    send(s, (const char*)pkt, 8 + L + 1, 0);
}

// 將非可列印字元替換成 '.' 以便在表格預覽 Payload
static void sanitize_preview(const unsigned char* in, uint16_t len, char* out, int outcap){
    int n = (len < (uint16_t)(outcap-1)) ? len : (outcap-1);
    for (int i = 0; i < n; ++i){
        unsigned char c = in[i];
        out[i] = (c >= 32 && c <= 126) ? (char)c : '.';
    }
    out[n] = '\0';
}

// 表格化列印封包：只在 P1 呼叫 (預覽一下封包長哪樣)
static void print_packet_table_full(const unsigned char* buf, uint16_t payload_len){
    unsigned char type = buf[2];
    unsigned char prio = buf[3];
    unsigned char flags= buf[4];
    unsigned char ttl  = buf[5];
    unsigned char len_lo = buf[6];
    unsigned char len_hi = buf[7];
    unsigned char ck = buf[8 + payload_len];

    char preview[40];
    sanitize_preview(&buf[8], payload_len, preview, sizeof(preview));

    printf("\n+--------+------+----------+--------+-----+---------+--------------------------------+----------+\n");
    printf("| Header | Type | Priority | Flags  | TTL | Length  | Payload (preview)              | Checksum |\n");
    printf("+--------+------+----------+--------+-----+---------+--------------------------------+----------+\n");
    printf("| %02X %02X  |  0x%02X |    %3u   | 0x%02X | %3u | %02X %02X  | %-30s |   0x%02X   |\n",
           buf[0], buf[1], type, prio, flags, ttl, len_lo, len_hi, preview, ck);
    printf("+--------+------+----------+--------+-----+---------+--------------------------------+----------+\n\n");

    // 額外提示 flag 位元
    if (flags){
        printf("Flags 說明：%s%s%s\n",
            (flags & FLAG_REQUIRE_ACK) ? "[REQUIRE_ACK] " : "",
            (flags & FLAG_SELF_DESTRUCT_EN) ? "[SELF_DESTRUCT] " : "",
            (flags & FLAG_COMPRESSED) ? "[COMPRESSED]" : "");
    }
}

int main(void){
    #ifdef _WIN32
    // 輸入/輸出都設定成 UTF-8 (這樣才能輸出中文，不然都是亂碼)
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0){ fprintf(stderr, "WSAStartup failed\n"); return 1; }

    SOCKET listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == INVALID_SOCKET){ fprintf(stderr, "socket failed\n"); return 1; }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(SERVER_PORT);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR){
        fprintf(stderr, "bind failed\n"); return 1;
    }
    if (listen(listen_fd, 16) == SOCKET_ERROR){
        fprintf(stderr, "listen failed\n"); return 1;
    }

    printf("Server listening on %d ...\n", SERVER_PORT);

    SOCKET clients[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; ++i) clients[i] = INVALID_SOCKET;
    int maxi = -1;

    fd_set allset, rset;
    FD_ZERO(&allset);
    FD_SET(listen_fd, &allset);
    int maxfd = (int)listen_fd;

    unsigned char buf[8 + MAX_PAYLOAD + 1];

    for (;;){
        rset = allset;
        int nready = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (nready == SOCKET_ERROR){ fprintf(stderr, "select error\n"); break; }

        if (FD_ISSET(listen_fd, &rset)){
            struct sockaddr_in cli; int clen = sizeof(cli);
            SOCKET cs = accept(listen_fd, (struct sockaddr*)&cli, &clen);
            if (cs != INVALID_SOCKET){
                int i;
                for (i = 0; i < MAX_CLIENTS; ++i){
                    if (clients[i] == INVALID_SOCKET){ clients[i] = cs; break; }
                }
                if (i == MAX_CLIENTS){ closesocket(cs); }
                else{
                    if (i > maxi) maxi = i;
                    FD_SET(cs, &allset);
                    if (cs > maxfd) maxfd = (int)cs;
                    printf("Client connected (idx=%d)\n", i);
                }
            }
            if (--nready <= 0) continue;
        }

        for (int i = 0; i <= maxi; ++i){
            SOCKET cs = clients[i];
            if (cs == INVALID_SOCKET) continue;
            if (!FD_ISSET(cs, &rset)) continue;

            int n = recv(cs, (char*)buf, sizeof(buf), 0);
            if (n <= 0){
                printf("Client idx=%d disconnected\n", i);
                closesocket(cs);
                FD_CLR(cs, &allset);
                clients[i] = INVALID_SOCKET;
                continue;
            }

            if (n < 9 || buf[0]!=MAGIC1 || buf[1]!=MAGIC2){ printf("bad packet\n"); continue; }
            unsigned char type = buf[2];
            unsigned char prio = buf[3];
            unsigned char flags= buf[4];
            // [5]自毀功能在relay完成
            uint16_t L = (uint16_t)(buf[6] | (buf[7]<<8));
            if (8 + L + 1 != n){ printf("len mismatch\n"); continue; }

            unsigned char* payload = &buf[8];
            unsigned char ck = buf[8+L];
            if (ck != xor_checksum(payload, L)){ printf("checksum error\n"); continue; }

            printf("\n=== Packet === type=0x%02X prio=%u flags=0x%02X len=%u\n", type, prio, flags, L);

            if (type == TYPE_DATA){
                if (prio == PRIO_DELAYED){
                    printf("[P0 延遲] 已保存（示意：不立即顯示內容）\n");
                } else if (prio == PRIO_IMMEDIATE){
                    printf("[P1 即時] 顯示：%.*s\n", L, (char*)payload);
                    print_packet_table_full(buf, L);
                } else if (prio == PRIO_EPHEMERAL){
                    printf("[P5 短暫] 顯示後即忘：%.*s\n", L, (char*)payload);
                } else if (prio == PRIO_MEDIA){
                    if (flags & FLAG_COMPRESSED){
                        unsigned char out[MAX_PAYLOAD];
                        int outlen = rle_decompress(payload, L, out, MAX_PAYLOAD);
                        if (outlen < 0) printf("[P6 多媒體] RLE 解壓失敗\n");
                        else printf("[P6 多媒體] 解壓後：%.*s\n", outlen, (char*)out);
                    } else {
                        printf("[P6 多媒體] 未壓縮：%.*s\n", L, (char*)payload);
                    }
                } else {
                    printf("[未知 prio=%u] 顯示：%.*s\n", prio, L, (char*)payload);
                }

                if (flags & FLAG_REQUIRE_ACK){
                    send_ack(cs, prio, "ACK");
                }
            } else if (type == TYPE_HEARTBEAT){
                printf("[心跳] 收到 HEARTBEAT → 回 ACK\n");
                send_ack(cs, prio, "ACK_HEARTBEAT");
            } else {
                printf("[其他 type=0x%02X]\n", type);
            }
        }
    }

    closesocket(listen_fd);
    WSACleanup();
    return 0;
}
