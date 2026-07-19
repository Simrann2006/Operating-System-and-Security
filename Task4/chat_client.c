#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_PORT 5555
#define BUFFER_SIZE  1024

/* Reads one line from the socket, stopping at '\n'. */
int recv_line(int sock, char *buf, int maxlen) {
    int i = 0;
    char c;
    while (i < maxlen - 1) {
        int r = recv(sock, &c, 1, 0);
        if (r == 0) return 0;
        if (r < 0) return -1;
        if (c == '\n') break;
        if (c != '\r') buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}

/* Sends a line, adding the newline the protocol uses as a terminator. */
void send_line(int sock, const char *msg) {
    char out[BUFFER_SIZE];
    snprintf(out, sizeof(out), "%s\n", msg);
    send(sock, out, strlen(out), 0);
}

int main(int argc, char *argv[]) {
    const char *server_ip = (argc > 1) ? argv[1] : "127.0.0.1";
    int port = (argc > 2) ? atoi(argv[2]) : DEFAULT_PORT;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket() failed");
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server address: %s\n", server_ip);
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect() failed - is the server running?");
        close(sock);
        return 1;
    }

    printf("Connected to %s:%d\n", server_ip, port);
    printf("Type a message to send it, 'ping' to ping the server, or 'quit' to disconnect.\n");

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) == 0) continue;

        if (strcmp(line, "quit") == 0) {
            send_line(sock, "QUIT");
            char reply[BUFFER_SIZE];
            recv_line(sock, reply, sizeof(reply));
            printf("Server: %s\n", reply);
            break;

        } else if (strcmp(line, "ping") == 0) {
            send_line(sock, "PING");

        } else {
            char cmd[BUFFER_SIZE + 5];
            snprintf(cmd, sizeof(cmd), "MSG %s", line);
            send_line(sock, cmd);
        }

        char reply[BUFFER_SIZE];
        int n = recv_line(sock, reply, sizeof(reply));
        if (n <= 0) {
            printf("Server closed the connection.\n");
            break;
        }
        printf("Server: %s\n", reply);
    }

    close(sock);
    return 0;
}