#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

// Total number of worker threads created in the program.
#define NUM_THREADS 3
// Number of times each thread increments the shared counter.
// A large value makes race conditions easier to observe.
#define INCREMENTS_PER_THREAD 500000 
// Number of scheduling rounds executed in Phase 2.
#define ROUNDS_EACH 3
// Simulated CPU time slice for Round Robin scheduling (microseconds).
#define TIME_SLICE_US 300000

// ---------------- PHASE 1: SHARED COUNTER ----------------
// Shared variable accessed by all threads.
// This is intentionally used to demonstrate race conditions
// and later protected using a mutex.
long shared_counter = 0;
// Mutex used to protect the shared counter.
// Only one thread can modify shared_counter at a time.
pthread_mutex_t counter_mutex;

// Controls whether synchronization is enabled. 
// 0 = Counter is updated without protection
//     (demonstrates race condition)
// 1 = Counter is protected using a mutex
//     (demonstrates the correct solution)
int use_mutex = 0;

// ---------------- PHASE 2: ROUND-ROBIN SCHEDULING STATE ----------------
// Stores the ID of the thread that is currently allowed
// to execute during the Round Robin simulation.
int current_turn = 0;
// Protects access to the scheduler state (current_turn)
// so multiple threads cannot modify it simultaneously.
pthread_mutex_t scheduler_mutex;
// Condition variable used to suspend threads until
// their scheduled turn arrives.
// Prevents busy waiting and improves efficiency.
pthread_cond_t  turn_cond;

// ---------------- PHASE 2: DEADLOCK-PREVENTION RESOURCES ----------------
// Two shared resources used to demonstrate
// deadlock prevention techniques.
pthread_mutex_t resource_A;
pthread_mutex_t resource_B;

// Structure used to pass a unique thread ID
// to each worker thread during creation.
typedef struct {
    int thread_id;
} ThreadArgs;

void acquire_no_hold_and_wait(pthread_mutex_t *first, pthread_mutex_t *second,
                               const char *first_name, const char *second_name,
                               int id) {
    while (1) {
        pthread_mutex_lock(first);
        if (pthread_mutex_trylock(second) == 0) {
            return;
        }
        printf("[Thread %d] %s busy, releasing %s and retrying...\n",
               id, second_name, first_name);
        pthread_mutex_unlock(first);
        usleep((rand() % 300 + 50) * 1000);
    }
}

void release_both(pthread_mutex_t *first, pthread_mutex_t *second) {
    pthread_mutex_unlock(second);
    pthread_mutex_unlock(first);
}

/*
------------------------------------------------------------
Thread Function - Phase 1

Each thread repeatedly increments the shared counter.

Phase 1a:
    Updates occur without synchronization,
    allowing race conditions.

Phase 1b:
    Updates are protected by a mutex,
    ensuring correct results.
------------------------------------------------------------
*/
void *race_and_fix_func(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    int id = args->thread_id;

    for (int i = 0; i < INCREMENTS_PER_THREAD; i++) {
        if (use_mutex) {
            pthread_mutex_lock(&counter_mutex);
            shared_counter++;
            pthread_mutex_unlock(&counter_mutex);
        } else {
            // Unsafe update.
            // Multiple threads may read and write the variable
            // simultaneously, producing inconsistent results.
            shared_counter++;
        }
    }

    printf("[Thread %d] done.\n", id);
    return NULL;
}

/*
------------------------------------------------------------
Thread Function - Phase 2

Implements a simple Round Robin scheduler.

Each thread:
1. Waits until it is its turn.
2. Executes for one simulated time slice.
3. Requests two shared resources.
4. Releases both resources.
5. Passes execution to the next thread.
------------------------------------------------------------
*/
void *phase2_scheduling_func(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    int id = args->thread_id;

    for (int round = 0; round < ROUNDS_EACH; round++) {
        pthread_mutex_lock(&scheduler_mutex);
        while (current_turn != id) {
            // Suspend the thread until the scheduler
            // assigns it the next CPU time slice.
            pthread_cond_wait(&turn_cond, &scheduler_mutex);
        }
        pthread_mutex_unlock(&scheduler_mutex);

        printf("[Thread %d] Turn %d — running...\n", id, round + 1);
        // Simulate CPU execution during the assigned
        // Round Robin time quantum.
        usleep(TIME_SLICE_US);

        if (id % 2 == 0) {
            acquire_no_hold_and_wait(&resource_A, &resource_B, "resource_A", "resource_B", id);
        } else {
            acquire_no_hold_and_wait(&resource_B, &resource_A, "resource_B", "resource_A", id);
        }
        printf("[Thread %d] Using both resources safely...\n", id);
        usleep(100000);
        release_both(&resource_A, &resource_B);

        pthread_mutex_lock(&scheduler_mutex);
        // Move the CPU to the next thread
        // following Round Robin scheduling.
        current_turn = (current_turn + 1) % NUM_THREADS;
        pthread_cond_broadcast(&turn_cond);
        pthread_mutex_unlock(&scheduler_mutex);
    }

    printf("[Thread %d] Phase 2 complete.\n", id);
    return NULL;
}

int main(void) {
    pthread_t threads[NUM_THREADS];
    ThreadArgs args[NUM_THREADS];

    pthread_mutex_init(&counter_mutex, NULL);
    pthread_mutex_init(&scheduler_mutex, NULL);
    pthread_cond_init(&turn_cond, NULL);
    pthread_mutex_init(&resource_A, NULL);
    pthread_mutex_init(&resource_B, NULL);

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
    }

    printf("=== OS Threading Application ===\n\n");

    // ---------------- PHASE 1a: RACE CONDITION (unprotected) ----------------
    printf("--- Phase 1a: Race Condition Demo (NO synchronization) ---\n");
    printf("Expected final count: %d\n", NUM_THREADS * INCREMENTS_PER_THREAD);

    use_mutex = 0;
    shared_counter = 0; // Reset the shared counter before starting the next demonstration.

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, race_and_fix_func, &args[i]);
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    printf("Actual final count (UNPROTECTED): %ld", shared_counter);
    if (shared_counter != NUM_THREADS * INCREMENTS_PER_THREAD)
        printf("   <-- race condition occurred, count is WRONG\n\n");
    else
        printf("   <-- happened to match this run, but is NOT guaranteed (try again)\n\n");

    // ---------------- PHASE 1b: MUTEX FIX (protected) ----------------
    printf("--- Phase 1b: Same Task, Now Protected With a Mutex ---\n");
    printf("Expected final count: %d\n", NUM_THREADS * INCREMENTS_PER_THREAD);

    use_mutex = 1;
    shared_counter = 0;

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, race_and_fix_func, &args[i]);
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    printf("Actual final count (MUTEX-PROTECTED): %ld   <-- always correct\n\n", shared_counter);

    // ---------------- PHASE 2: ROUND-ROBIN + DEADLOCK PREVENTION ----------------
    printf("--- Phase 2: Round-Robin Scheduling + Deadlock Prevention Demo ---\n\n");

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, phase2_scheduling_func, &args[i]);
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    printf("\n=== All phases complete. No deadlock occurred despite ");
    printf("threads requesting resources in different orders. ===\n");

    pthread_mutex_destroy(&counter_mutex);
    pthread_mutex_destroy(&scheduler_mutex);
    pthread_cond_destroy(&turn_cond);
    pthread_mutex_destroy(&resource_A);
    pthread_mutex_destroy(&resource_B);

    return 0;
}