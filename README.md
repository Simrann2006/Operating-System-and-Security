# ST5004CEM - Operating Systems and Security

Simran Chaudhary · 240751 · Softwarica College of IT & E-Commerce

This repo contains my four-part submission for ST5004CEM. Each part is a standalone C program that implements a different operating-systems topic.

## Layout

```
.
├── Task1/     process management & threading
├── Task2/     virtual memory / paging simulator
├── Task3/     secure vault (file system + security)
├── Task4/     socket-based multi-user chat
└── README.md
```

## Requirements

- gcc, Linux/Ubuntu
- `-lpthread` for Tasks 1 and 4

---

## Task 1 — Threads, Race Conditions & Deadlock Avoidance

`Task1/main.c` runs two back-to-back demos:

- **Unsafe vs. safe counter.** Three threads hammer a shared `long` counter 500,000 times each. Run once with no locking (the total comes out wrong/inconsistent because increments overlap), then run again wrapping each increment in a mutex (the total is now always correct).
- **Round robin + deadlock-free resource sharing.** The same three threads then take turns executing under a simple round-robin scheduler — a shared `current_turn` value plus a condition variable puts each thread to sleep until it's their turn, avoiding busy-waiting. During its turn, each thread grabs two shared "resources"; even-numbered threads grab them in the order A→B, odd-numbered threads grab them B→A, which is the standard recipe for deadlock. It's avoided with a no-hold-and-wait pattern: lock the first resource, `trylock` the second, and if that fails, release the first and retry after a short random pause instead of sitting there holding it.

```
cd Task1
gcc -Wall -o main main.c -lpthread
./main
```

## Task 2 — Virtual Memory / Page Replacement Simulator

`Task2/main.c` takes the frame count and page size as command-line arguments and runs a fixed 20-reference access pattern through **both** FIFO and LRU so the two algorithms are compared on identical input. For every reference it prints whether it was a hit or a fault, which frame got filled or evicted, and a small ASCII diagram of memory state at that point; it finishes with a side-by-side table of total hits/faults and hit/miss ratio for each algorithm.

```
cd Task2
gcc -Wall -o main main.c
./main <num_frames> <page_size_bytes>
# e.g. ./main 4 256
```

## Task 3 — Secure Vault (File System + Security)

`Task3/main.c` is a terminal "vault" app with its own account system and encrypted file store (`vault_data/`):

- Accounts register/log in with passwords stored as a salted, iterated hash (never plaintext); passwords are typed with terminal echo disabled.
- Every stored file gets a sidecar `.meta` entry recording owner, group, a 9-character `rwxrwxrwx`-style permission string, and whether it's currently encrypted.
- Read/write/delete/chmod requests are checked against that permission string based on whether the logged-in user is the owner, in the same group, or neither.
- Files can be encrypted/decrypted in place with a passphrase using a symmetric XOR cipher.
- Every action (register, login, create, read, write, chmod, encrypt, decrypt, delete) is timestamped and appended to `vault_data/audit.log`, whether it succeeded or failed and why.

```
cd Task3
gcc -Wall -o main main.c
./main
```

## Task 4 — TCP Chat Server & Client (Sockets + IPC)

`Task4/chat_server.c` and `Task4/chat_client.c` implement a small multi-user chat system over raw TCP sockets with a plain-text, line-terminated protocol (`LOGIN`, `REGISTER`, `MSG`, `PING`, `QUIT`, …):

- The server accepts connections, spawns one thread per client, and requires `REGISTER`/`LOGIN` (same salted-hash scheme as Task 3) before any chat command is accepted.
- Connected clients are tracked in a fixed-size array guarded by a mutex, since multiple client threads read and modify it concurrently (adding, removing, broadcasting).
- Any `MSG` from one client is broadcast to everyone else currently connected; join/leave notices are broadcast automatically.
- The client hides password entry, authenticates in a retry loop rather than dropping the connection on the first wrong password, and runs a separate receiver thread so incoming messages appear immediately instead of only after the user presses enter.

```
cd Task4
gcc -Wall -o chat_server chat_server.c -lpthread
gcc -Wall -o chat_client chat_client.c -lpthread
./chat_server            # terminal 1
./chat_client             # terminal 2, 3, ... one per user
```

---