#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define DEFAULT_PORT 5555
#define BUFFER_SIZE  1024
#define USERS_FILE   "chat_users.db"
#define MAX_NAME     64
#define MAX_PASS     128

#define CLR_RESET  "\033[0m"
#define CLR_OK     "\033[32m"   /* green  - success   */
#define CLR_ERR    "\033[31m"   /* red    - failure   */
#define CLR_INFO   "\033[36m"   /* cyan   - headings  */

static void ok(const char *msg)  { printf(CLR_OK  "%s" CLR_RESET "\n", msg); }
static void err(const char *msg) { printf(CLR_ERR "%s" CLR_RESET "\n", msg); }
static void info(const char *msg) { printf(CLR_INFO "%s" CLR_RESET "\n", msg); }

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

/* Passwords are stored as salted hashes */

/* Generates a hash value from a string. */
unsigned long simple_hash(const char *s) {
    unsigned long h = 5381;
    int c;
    while ((c = *s++)) h = ((h << 5) + h) + c;
    return h;
}

/* Combines the password with the salt and creates the stored hash. */
void make_hash(const char *password, const char *salt, char *out_hex) {
    char mix[256];
    snprintf(mix, sizeof(mix), "%s:%s", salt, password);
    unsigned long h = simple_hash(mix);
    for (int i = 0; i < 3000; i++) {
        char step[64];
        snprintf(step, sizeof(step), "%lu:%s:%d", h, salt, i);
        h = simple_hash(step);
    }
    snprintf(out_hex, 17, "%016lx", h);
}

/* Creates a random hexadecimal salt for each user. */
void make_salt(char *out, int len) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < len; i++) out[i] = hex[rand() % 16];
    out[len] = '\0';
}

/* Checks if a username is already registered. */
int user_exists(const char *username) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return 0;
    char line[256], stored[MAX_NAME];
    while (fgets(line, sizeof(line), f)) {
        sscanf(line, "%63[^:]", stored);
        if (strcmp(stored, username) == 0) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

/* Registers a new account: username:salt:hash appended to the database. */
int register_user(const char *username, const char *password) {
    if (user_exists(username)) return 0;
    char salt[9];
    make_salt(salt, 8);
    char hash[17];
    make_hash(password, salt, hash);

    FILE *f = fopen(USERS_FILE, "a");
    if (!f) return 0;
    fprintf(f, "%s:%s:%s\n", username, salt, hash);
    fclose(f);
    return 1;
}

/* Verifies a username/password pair against the database. */
int login_user(const char *username, const char *password) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return 0;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char u[MAX_NAME], salt[16], hash[17];
        if (sscanf(line, "%63[^:]:%15[^:]:%16[^\n]", u, salt, hash) != 3) continue;
        if (strcmp(u, username) != 0) continue;

        char attempt[17];
        make_hash(password, salt, attempt);
        fclose(f);
        return strcmp(attempt, hash) == 0;
    }
    fclose(f);
    return 0;
}

/* Handles the pre-login phase: lets a client REGISTER and/or LOGIN,
   looping so a failed attempt doesn't immediately disconnect user.
   Returns 1 and fills username_out once LOGIN succeeds. */
int authenticate_session(int client_sock, char *username_out) {
    char buffer[BUFFER_SIZE];

    while (1) {
        int n = recv_line(client_sock, buffer, sizeof(buffer));
        if (n <= 0) return 0;

        char cmd[16], user[MAX_NAME], pass[MAX_PASS];
        int parsed = sscanf(buffer, "%15s %63s %127s", cmd, user, pass);
        if (parsed != 3) {
            send_line(client_sock, "ERROR Expected: LOGIN <user> <pass> or REGISTER <user> <pass>");
            continue;
        }

        if (strcmp(cmd, "REGISTER") == 0) {
            if (register_user(user, pass)) {
                send_line(client_sock, "REGISTER_OK Account created, now send LOGIN");
            } else {
                send_line(client_sock, "REGISTER_FAIL Username already taken");
            }
            continue;
        }

        if (strcmp(cmd, "LOGIN") == 0) {
            if (login_user(user, pass)) {
                strcpy(username_out, user);
                char welcome[128];
                snprintf(welcome, sizeof(welcome), "LOGIN_OK Welcome, %s!", user);
                send_line(client_sock, welcome);
                return 1;
            }
            send_line(client_sock, "LOGIN_FAIL Invalid username or password");
            continue;
        }

        send_line(client_sock, "ERROR Unknown command, expected LOGIN or REGISTER");
    }
}

/* Handles one authenticated client's commands until QUIT or disconnect. */
void handle_client(int client_sock, const char *username) {
    char buffer[BUFFER_SIZE];

    while (1) {
        int n = recv_line(client_sock, buffer, sizeof(buffer));
        if (n <= 0) {
            char msg[128];
            snprintf(msg, sizeof(msg), "%s disconnected.", username);
            err(msg);
            break;
        }

        if (strncmp(buffer, "MSG ", 4) == 0) {
            const char *text = buffer + 4;
            printf(CLR_INFO "[%s]:" CLR_RESET " %s\n", username, text);
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
    srand((unsigned int)time(NULL));

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

    printf(CLR_INFO "Server listening on port %d..." CLR_RESET "\n", port);

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
    if (client_sock < 0) {
        perror("accept() failed");
        close(server_sock);
        return 1;
    }
    info("Client connected, awaiting login...");

    char username[MAX_NAME];
    if (authenticate_session(client_sock, username)) {
        char msg[96];
        snprintf(msg, sizeof(msg), "%s authenticated.", username);
        ok(msg);
        handle_client(client_sock, username);
    } else {
        err("Client disconnected before logging in.");
    }

    close(client_sock);
    close(server_sock);
    return 0;
}