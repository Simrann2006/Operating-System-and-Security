#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define DEFAULT_PORT 5555
#define BUFFER_SIZE  1024

typedef struct {
    const char *username;
    const char *password;
} Credential;

Credential valid_users[] = {
    {"alice", "alicepass"},
    {"bob",   "bobpass"},
    {"carol", "carolpass"}
};
#define NUM_VALID_USERS (sizeof(valid_users) / sizeof(valid_users[0]))

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

/* Checks a username/password pair against the credential table. */
int authenticate(const char *username, const char *password) {
    for (size_t i = 0; i < NUM_VALID_USERS; i++) {
        if (strcmp(username, valid_users[i].username) == 0 &&
            strcmp(password, valid_users[i].password) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Reads the LOGIN line and checks it. Returns 1 and fills username
   on success, 0 on failure (malformed line or bad credentials). */
int handle_login(int client_sock, char *username_out) {
    char buffer[BUFFER_SIZE];
    int n = recv_line(client_sock, buffer, sizeof(buffer));
    if (n <= 0) return 0;

    char cmd[16], user[64], pass[64];
    int parsed = sscanf(buffer, "%15s %63s %63s", cmd, user, pass);

    if (parsed != 3 || strcmp(cmd, "LOGIN") != 0) {
        send_line(client_sock, "ERROR Expected: LOGIN <username> <password>");
        return 0;
    }

    if (!authenticate(user, pass)) {
        send_line(client_sock, "LOGIN_FAIL Invalid username or password");
        return 0;
    }

    strcpy(username_out, user);
    char welcome[128];
    snprintf(welcome, sizeof(welcome), "LOGIN_OK Welcome, %s!", user);
    send_line(client_sock, welcome);
    return 1;
}

/* Handles one authenticated client's commands until QUIT or disconnect. */
void handle_client(int client_sock, const char *username) {
    char buffer[BUFFER_SIZE];

    while (1) {
        int n = recv_line(client_sock, buffer, sizeof(buffer));
        if (n <= 0) {
            printf("%s disconnected.\n", username);
            break;
        }

        if (strncmp(buffer, "MSG ", 4) == 0) {
            const char *text = buffer + 4;
            printf("[%s]: %s\n", username, text);
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
    printf("Client connected, awaiting login...\n");

    char username[64];
    if (handle_login(client_sock, username)) {
        printf("%s authenticated.\n", username);
        handle_client(client_sock, username);
    } else {
        printf("Authentication failed, closing connection.\n");
    }

    close(client_sock);
    close(server_sock);
    return 0;
}