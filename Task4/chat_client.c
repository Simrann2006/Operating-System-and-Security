#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_PORT 5555
#define BUFFER_SIZE  1024

#define CLR_RESET  "\033[0m"
#define CLR_OK     "\033[32m"   /* green  - success   */
#define CLR_ERR    "\033[31m"   /* red    - failure   */
#define CLR_INFO   "\033[36m"   /* cyan   - headings  */
#define CLR_PROMPT "\033[35m"   /* magenta - prompts  */

static void ok(const char *msg)  { printf(CLR_OK  "%s" CLR_RESET "\n", msg); }
static void err(const char *msg) { printf(CLR_ERR "%s" CLR_RESET "\n", msg); }

int sock;
int running = 1;

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

/* Reads a password with terminal echo turned off. */
void read_hidden(const char *prompt, char *buf, int size) {
    struct termios oldt, newt;
    printf("%s", prompt);
    fflush(stdout);
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    fgets(buf, size, stdin);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
    buf[strcspn(buf, "\n")] = '\0';
}

/* Handles the pre-login phase: lets the user register and/or log in,
   retrying on failure instead of giving up after one bad attempt.
   Returns 1 once LOGIN succeeds. */
int authenticate(int sock) {
    char choice[8], username[64], password[64];

    while (1) {
        printf("\n" CLR_INFO "1) Register\n2) Login" CLR_RESET "\n");
        printf(CLR_PROMPT "Choose: " CLR_RESET);
        fflush(stdout);
        fgets(choice, sizeof(choice), stdin);

        printf(CLR_PROMPT "Username: " CLR_RESET);
        fflush(stdout);
        fgets(username, sizeof(username), stdin);
        username[strcspn(username, "\n")] = '\0';
        read_hidden(CLR_PROMPT "Password: " CLR_RESET, password, sizeof(password));

        char cmd[16];
        strcpy(cmd, (choice[0] == '1') ? "REGISTER" : "LOGIN");

        char line[160];
        snprintf(line, sizeof(line), "%s %s %s", cmd, username, password);
        send_line(sock, line);

        char response[BUFFER_SIZE];
        int n = recv_line(sock, response, sizeof(response));
        if (n <= 0) {
            err("Server closed the connection.");
            return 0;
        }

        if (strncmp(response, "LOGIN_OK", 8) == 0) {
            char msg[128];
            snprintf(msg, sizeof(msg), "Login successful. Welcome, %s!", username);
            ok(msg);
            return 1;
        } else if (strncmp(response, "LOGIN_FAIL", 10) == 0) {
            err("Login failed: invalid username or password.");
        } else if (strncmp(response, "REGISTER_OK", 11) == 0) {
            ok("Registration successful! You can now log in.");
        } else if (strncmp(response, "REGISTER_FAIL", 13) == 0) {
            err("Registration failed: that username is already taken.");
        } else {
            err(response);
        }
        /* loop and try again */
    }
}

/* Continuously prints whatever the server sends - runs on its own
   thread so a message from another client shows up immediately,
   even while this client is just sitting idle waiting for input. */
void *receiver_thread(void *arg) {
    (void)arg;
    char buf[BUFFER_SIZE];
    while (running) {
        int n = recv_line(sock, buf, sizeof(buf));
        if (n <= 0) {
            if (running) err("Disconnected from server.");
            running = 0;
            break;
        }
        printf(CLR_INFO "%s" CLR_RESET "\n", buf);
        fflush(stdout);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    const char *server_ip = (argc > 1) ? argv[1] : "127.0.0.1";
    int port = (argc > 2) ? atoi(argv[2]) : DEFAULT_PORT;

    sock = socket(AF_INET, SOCK_STREAM, 0);
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

    if (!authenticate(sock)) {
        close(sock);
        return 1;
    }

    pthread_t tid;
    pthread_create(&tid, NULL, receiver_thread, NULL);
    pthread_detach(tid);

    printf("\nType a message to send it, 'ping' to ping the server, or 'quit' to disconnect.\n");

    char line[BUFFER_SIZE];
    while (running && fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) == 0) continue;

        if (strcmp(line, "quit") == 0) {
            send_line(sock, "QUIT");
            usleep(200000); /* let the receiver thread print the server's BYE first */
            running = 0;
            break;

        } else if (strcmp(line, "ping") == 0) {
            send_line(sock, "PING");

        } else {
            char cmd[BUFFER_SIZE + 5];
            snprintf(cmd, sizeof(cmd), "MSG %s", line);
            send_line(sock, cmd);
        }
    }

    close(sock);
    return 0;
}