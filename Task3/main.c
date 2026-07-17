#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>

#define DATA_DIR   "vault_data"
#define USERS_FILE "vault_data/users.db"
#define AUDIT_FILE "vault_data/audit.log"

#define MAX_NAME  32
#define MAX_PASS  128
#define MAX_LINE  256

/* colours used for status lines */
#define CLR_RESET  "\033[0m"
#define CLR_OK     "\033[32m"   /* green  - success   */
#define CLR_ERR    "\033[31m"   /* red    - failure   */
#define CLR_INFO   "\033[36m"   /* cyan   - headings  */
#define CLR_PROMPT "\033[35m"   /* magenta - prompts  */

static char session_user[MAX_NAME]  = "";
static char session_group[MAX_NAME] = "";
static int  session_active = 0;

static void section(const char *title) {
    printf("\n" CLR_INFO "[ %s ]" CLR_RESET "\n", title);
    printf("------------------------------------------\n");
}

static void ok(const char *msg)  { printf(CLR_OK  "%s" CLR_RESET "\n", msg); }
static void err(const char *msg) { printf(CLR_ERR "%s" CLR_RESET "\n", msg); }

static void strip_nl(char *s) {
    size_t n = strlen(s);
    if (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[n - 1] = '\0';
}

static void ask(const char *prompt, char *buf, int size) {
    printf(CLR_PROMPT "%s" CLR_RESET, prompt);
    if (!fgets(buf, size, stdin)) { printf("\nBye.\n"); exit(0); }
    strip_nl(buf);
}

/* password entry with terminal echo turned off */
static void ask_secret(const char *prompt, char *buf, int size) {
    struct termios old_t, new_t;
    printf(CLR_PROMPT "%s" CLR_RESET, prompt);
    fflush(stdout);

    tcgetattr(STDIN_FILENO, &old_t);
    new_t = old_t;
    new_t.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_t);

    int got = (fgets(buf, size, stdin) != NULL);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
    printf("\n");

    if (!got) { printf("Bye.\n"); exit(0); }
    strip_nl(buf);
}

/* Creates the folder used to store all vault files. */
static void setup_storage(void) {
    mkdir(DATA_DIR, 0700);
}

/* Writes user actions such as login and registration
   into the audit log with the current date and time. */
static void audit(const char *user, const char *action, const char *result) {
    FILE *f = fopen(AUDIT_FILE, "a");
    if (!f) return;
    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(f, "[%s] user=%-12s action=%-10s result=%s\n",
            ts, (user && user[0]) ? user : "-", action, result);
    fclose(f);
}

/* Passwords are stored as hashes instead of plain text.
   A random salt is added so users with the same password
   will still have different stored hash values. */

/* Generates a hash value from a string. */
static unsigned long simple_hash(const char *s) {
    unsigned long h = 5381;
    int c;
    while ((c = *s++)) h = ((h << 5) + h) + c;
    return h;
}

/* Combines the password with the salt and creates
   the final hash that will be stored. */
static void make_hash(const char *password, const char *salt, char *out_hex) {
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
static void make_salt(char *out, int len) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < len; i++) out[i] = hex[rand() % 16];
    out[len] = '\0';
}

/* Checks if the username already exists before
   creating a new account. */
static int user_exists(const char *username) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return 0;
    char line[MAX_LINE], stored[MAX_NAME];
    while (fgets(line, sizeof(line), f)) {
        sscanf(line, "%31[^:]", stored);
        if (strcmp(stored, username) == 0) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

/* Registers a new user by saving the username,
   password hash, salt and group into the database. */
static int do_register(const char *username, const char *password, const char *group) {
    if (user_exists(username)) return 0;

    char salt[9];
    make_salt(salt, 8);
    char hash[17];
    make_hash(password, salt, hash);

    FILE *f = fopen(USERS_FILE, "a");
    if (!f) return 0;
    fprintf(f, "%s:%s:%s:%s\n", username, salt, hash, group);
    fclose(f);
    return 1;
}

/* Verifies the entered username and password
   against the stored account details. */
static int do_login(const char *username, const char *password, char *out_group) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return 0;

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        char u[MAX_NAME], salt[16], hash[17], grp[MAX_NAME];
        if (sscanf(line, "%31[^:]:%15[^:]:%16[^:]:%31[^\n]", u, salt, hash, grp) != 4)
            continue;
        if (strcmp(u, username) != 0) continue;

        char attempt[17];
        make_hash(password, salt, attempt);
        fclose(f);
        if (strcmp(attempt, hash) == 0) {
            strcpy(out_group, grp);
            return 1;
        }
        return 0;
    }
    fclose(f);
    return 0;
}

/* Functions below handle the different menu screens
   shown to the user. */

/* Registration screen where a new account is created. */
static void screen_register(void) {
    section("Register");
    char user[MAX_NAME], pass[MAX_PASS], confirm[MAX_PASS], group[MAX_NAME];

    ask("Username : ", user, sizeof(user));
    ask_secret("Password : ", pass, sizeof(pass));
    ask_secret("Confirm  : ", confirm, sizeof(confirm));

    if (strcmp(pass, confirm) != 0) {
        err("Passwords do not match.");
        audit(user, "REGISTER", "FAILED (mismatch)");
        return;
    }

    ask("Group    : ", group, sizeof(group));

    if (do_register(user, pass, group)) {
        ok("Account created. You can log in now.");
        audit(user, "REGISTER", "SUCCESS");
    } else {
        err("That username is already taken.");
        audit(user, "REGISTER", "FAILED (duplicate)");
    }
}

/* Login screen that checks the user's credentials. */
static int screen_login(void) {
    section("Login");
    char user[MAX_NAME], pass[MAX_PASS];

    ask("Username : ", user, sizeof(user));
    ask_secret("Password : ", pass, sizeof(pass));

    if (do_login(user, pass, session_group)) {
        strcpy(session_user, user);
        session_active = 1;
        ok("Login successful.");
        audit(user, "LOGIN", "SUCCESS");
        return 1;
    }

    err("Invalid username or password.");
    audit(user, "LOGIN", "FAILED");
    return 0;
}

/* Vault menu shown after a successful login. */
static void vault_menu(void) {
    char choice[8];
    while (1) {
        printf("\n" CLR_INFO "[ Vault - %s (%s) ]" CLR_RESET "\n",
               session_user, session_group);
        printf("1) Logout\n");
        ask("Choose: ", choice, sizeof(choice));

        if (strcmp(choice, "1") == 0) {
            audit(session_user, "LOGOUT", "SUCCESS");
            session_active = 0;
            return;
        }
        err("Invalid option.");
    }
}

/* Displays the main menu and lets the user
   register, log in or exit the program. */
static void main_menu(void) {
    char choice[8];
    while (1) {
        printf("\n" CLR_INFO "[ Secure Vault ]" CLR_RESET "\n");
        printf("1) Register\n2) Login\n3) Exit\n");
        ask("Choose: ", choice, sizeof(choice));

        if (strcmp(choice, "1") == 0) {
            screen_register();
        } else if (strcmp(choice, "2") == 0) {
            if (screen_login()) vault_menu();
        } else if (strcmp(choice, "3") == 0) {
            printf("Bye.\n");
            return;
        } else {
            err("Invalid option.");
        }
    }
}

int main(void) {
    srand((unsigned int)time(NULL));
    setup_storage();
    main_menu();
    return 0;
}