#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define DEFAULT_PORT 5555
#define BUFFER_SIZE  1024

/* Reads one line from the socket, stopping at '\n'. */
int recv_line(int sock, char *buf, int maxlen) {
    int i = 0;
    char c;
    while (i < maxlen - 1) {
        int r = recv(sock, &c, 1, 0);
        if (r == 0) return 0;   /* connection closed */
        if (r < 0) return -1;   /* socket error */
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

/* Handles one client's commands until QUIT or disconnect. */
void handle_client(int client_sock) {
    char buffer[BUFFER_SIZE];

    while (1) {
        int n = recv_line(client_sock, buffer, sizeof(buffer));
        if (n <= 0) {
            printf("Client disconnected.\n");
            break;
        }

        if (strncmp(buffer, "MSG ", 4) == 0) {
            const char *text = buffer + 4;
            printf("Message: %s\n", text);
            char reply[BUFFER_SIZE];
            snprintf(reply, sizeof(reply), "ACK %s", text);
            send_line(client_sock, reply);

        } else if (strcmp(buffer, "PING") == 0) {
            send_line(client_sock, "PONG");

        } else if (strcmp(buffer, "QUIT") == 0) {
            send_line(client_sock, "BYE");
            break;

        } else {
            send_line(client_sock, "ERROR Unknown command");
        }
    }
}

int main(int argc, char *argv[]) {
    int port = (argc > 1) ? atoi(argv[1]) : DEFAULT_PORT;

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket() failed");
        return 1;
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind() failed");
        close(server_sock);
        return 1;
    }

    if (listen(server_sock, 1) < 0) {
        perror("listen() failed");
        close(server_sock);
        return 1;
    }

    printf("Server listening on port %d...\n", port);

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
    if (client_sock < 0) {
        perror("accept() failed");
        close(server_sock);
        return 1;
    }
    printf("Client connected.\n");

    handle_client(client_sock);

    close(client_sock);
    close(server_sock);
    return 0;
}