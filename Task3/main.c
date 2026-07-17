#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#define DATA_DIR    "vault_data"
#define USERS_FILE  "vault_data/users.db"
#define AUDIT_FILE  "vault_data/audit.log"
#define STORAGE_DIR "vault_data/storage"
#define META_DIR    "vault_data/meta"

#define MAX_NAME     32
#define MAX_PASS     128
#define MAX_LINE     256
#define MAX_FILENAME 64
#define MAX_PATH     256

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

/* Creates the folders used to store all vault files and metadata. */
static void setup_storage(void) {
    mkdir(DATA_DIR, 0700);
    mkdir(STORAGE_DIR, 0700);
    mkdir(META_DIR, 0700);
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

/* Helper functions for creating file and metadata paths. */

/* Creates the full path where the file will be stored. */
static void storage_path(const char *filename, char *out) {
    snprintf(out, MAX_PATH, "%s/%s", STORAGE_DIR, filename);
}

/* Creates the full path for the file's metadata. */
static void meta_path(const char *filename, char *out) {
    snprintf(out, MAX_PATH, "%s/%s.meta", META_DIR, filename);
}

/* Checks if a file exists at the given path. */
static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

/* Each file has a metadata file that stores
   the owner, group and permission settings. */

/* Saves metadata for a file: owner, group, and permissions. */
static void write_meta(const char *filename, const char *owner,
                        const char *group, const char *perms) {
    char path[MAX_PATH];
    meta_path(filename, path);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "owner=%s\ngroup=%s\nperms=%s\n", owner, group, perms);
    fclose(f);
}

/* Reads the saved metadata for a file. */
static int read_meta(const char *filename, char *owner, char *group, char *perms) {
    char path[MAX_PATH];
    meta_path(filename, path);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        strip_nl(line);
        if (strncmp(line, "owner=", 6) == 0) strcpy(owner, line + 6);
        else if (strncmp(line, "group=", 6) == 0) strcpy(group, line + 6);
        else if (strncmp(line, "perms=", 6) == 0) strcpy(perms, line + 6);
    }
    fclose(f);
    return 1;
}

/* File permissions follow the format:
   owner | group | others
   Example: rw-r----- */

/* Checks if the permission string is valid. */
static int valid_perms(const char *perms) {
    if (strlen(perms) != 9) return 0;
    const char expected[9] = { 'r','w','x','r','w','x','r','w','x' };
    for (int i = 0; i < 9; i++)
        if (perms[i] != '-' && perms[i] != expected[i]) return 0;
    return 1;
}

/* Finds whether the current user is
   the owner, in the same group, or another user. */
static char relation_to(const char *username, const char *user_group,
                         const char *owner, const char *file_group) {
    if (strcmp(username, owner) == 0) return 'o';
    if (strcmp(user_group, file_group) == 0) return 'g';
    return 't';
}

/* Checks if the user has the required permission (r/w/x) for a file. */
static int has_permission(const char *perms, char relation, char action) {
    int base   = (relation == 'o') ? 0 : (relation == 'g') ? 3 : 6;
    int offset = (action == 'r') ? 0 : (action == 'w') ? 1 : 2;
    return perms[base + offset] == action;
}

/* Creates a new empty file with the specified permissions and metadata. */
static int create_vault_file(const char *filename, const char *perms) {
    char path[MAX_PATH];
    storage_path(filename, path);
    
    if (file_exists(path)) {
        return 0;
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        return 0;
    }
    fclose(f);

    write_meta(filename, session_user, session_group, perms);
    return 1;
}

/* Lists all files in the vault with their metadata. */
static void list_vault_files(void) {
    DIR *dir = opendir(META_DIR);
    if (!dir) {
        printf("\nNo files found.\n");
        return;
    }
    
    printf("\n" CLR_INFO "Files in vault:" CLR_RESET "\n");
    printf("%-20s %-12s %-10s %s\n", "Filename", "Owner", "Group", "Perms");
    printf("--------------------------------------------------------\n");
    
    struct dirent *entry;
    int count = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        char *ext = strstr(entry->d_name, ".meta");
        if (ext && strlen(ext) == 5) {
            char filename[MAX_FILENAME];
            strncpy(filename, entry->d_name, ext - entry->d_name);
            filename[ext - entry->d_name] = '\0';
            
            char owner[MAX_NAME], group[MAX_NAME], perms[16];
            if (read_meta(filename, owner, group, perms)) {
                printf("%-20s %-12s %-10s %s\n", filename, owner, group, perms);
                count++;
            }
        }
    }
    
    closedir(dir);
    printf("--------------------------------------------------------\n");
    printf("Total: %d file(s)\n", count);
}

/* Displays detailed information about a specific file. */
static void file_info(const char *filename) {
    char owner[MAX_NAME], group[MAX_NAME], perms[16];
    
    if (!read_meta(filename, owner, group, perms)) {
        err("File not found.");
        audit(session_user, "FILE_INFO", "FAILED (not found)");
        return;
    }
    
    printf("\nFile: %s\n", filename);
    printf("  Owner: %s\n", owner);
    printf("  Group: %s\n", group);
    printf("  Permissions: %s\n", perms);
    
    char relation = relation_to(session_user, session_group, owner, group);
    printf("  Your relation: %s\n", 
           relation == 'o' ? "owner" : 
           relation == 'g' ? "group member" : "other");
    
    printf("  Permissions for you: ");
    if (has_permission(perms, relation, 'r')) printf("r"); else printf("-");
    if (has_permission(perms, relation, 'w')) printf("w"); else printf("-");
    if (has_permission(perms, relation, 'x')) printf("x"); else printf("-");
    printf("\n");
}

/* Deletes a file if the user has write permission. */
static void delete_vault_file(const char *filename) {
    char owner[MAX_NAME], group[MAX_NAME], perms[16];
    
    if (!read_meta(filename, owner, group, perms)) {
        err("File not found.");
        audit(session_user, "DELETE", "FAILED (not found)");
        return;
    }
    
    char relation = relation_to(session_user, session_group, owner, group);
    if (!has_permission(perms, relation, 'w')) {
        err("Permission denied - you need write permission.");
        audit(session_user, "DELETE", "FAILED (permission denied)");
        return;
    }
    
    char path[MAX_PATH];
    storage_path(filename, path);
    if (unlink(path) != 0) {
        err("Failed to delete file.");
        audit(session_user, "DELETE", "FAILED (I/O error)");
        return;
    }
    
    /* Remove the metadata file */
    meta_path(filename, path);
    unlink(path);
    
    ok("File deleted successfully.");
    audit(session_user, "DELETE", "SUCCESS");
}

/* file operation screens */

/* Screen for creating a new file with permission settings. */
static void screen_create_file(void) {
    section("Create File");
    char filename[MAX_FILENAME];
    ask("Filename : ", filename, sizeof(filename));

    char path[MAX_PATH];
    storage_path(filename, path);
    if (file_exists(path)) {
        err("A file with that name already exists.");
        audit(session_user, "CREATE", "FAILED (exists)");
        return;
    }

    printf("Permission format is 9 characters: owner|group|other, e.g. rw-r-----\n");
    char perms[16];
    ask("Permissions [default rw-r-----] : ", perms, sizeof(perms));
    if (strlen(perms) == 0) {
        strcpy(perms, "rw-r-----");
    } else if (!valid_perms(perms)) {
        err("Invalid format, using default rw-r-----.");
        strcpy(perms, "rw-r-----");
    }

    if (create_vault_file(filename, perms)) {
        ok("File created.");
        printf("  owner=%s  group=%s  perms=%s\n", session_user, session_group, perms);
        audit(session_user, "CREATE", "SUCCESS");
    } else {
        err("Could not create file.");
        audit(session_user, "CREATE", "FAILED (I/O error)");
    }
}

/* Screen for displaying file information. */
static void screen_file_info(void) {
    section("File Info");
    char filename[MAX_FILENAME];
    ask("Filename : ", filename, sizeof(filename));
    file_info(filename);
}

/* Screen for deleting a file. */
static void screen_delete_file(void) {
    section("Delete File");
    char filename[MAX_FILENAME];
    ask("Filename to delete : ", filename, sizeof(filename));
    
    char confirm[8];
    ask("Are you sure? (y/n) : ", confirm, sizeof(confirm));
    if (strcmp(confirm, "y") != 0 && strcmp(confirm, "Y") != 0) {
        ok("Deletion cancelled.");
        return;
    }
    
    delete_vault_file(filename);
}

/* Vault menu shown after a successful login. */
static void vault_menu(void) {
    char choice[8];
    while (1) {
        printf("\n" CLR_INFO "[ Vault - %s (%s) ]" CLR_RESET "\n",
               session_user, session_group);
        printf("1) Create file\n");
        printf("2) List files\n");
        printf("3) File info\n");
        printf("4) Delete file\n");
        printf("5) Logout\n");
        ask("Choose: ", choice, sizeof(choice));

        if (strcmp(choice, "1") == 0) {
            screen_create_file();
        } else if (strcmp(choice, "2") == 0) {
            list_vault_files();
        } else if (strcmp(choice, "3") == 0) {
            screen_file_info();
        } else if (strcmp(choice, "4") == 0) {
            screen_delete_file();
        } else if (strcmp(choice, "5") == 0) {
            audit(session_user, "LOGOUT", "SUCCESS");
            session_active = 0;
            return;
        } else {
            err("Invalid option.");
        }
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