#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Total number of page references used during the simulation.
// The same reference string is used for both algorithms to
// ensure a fair comparison.
#define REF_STRING_LENGTH 20
// Maximum number of physical memory frames supported.
#define MAX_FRAMES        32

// ANSI escape codes used to format terminal output with
// colors and text styles for better readability.
#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define DIM     "\033[2m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define RED     "\033[31m"
#define CYAN    "\033[36m"

/*
------------------------------------------------------------
generate_reference_string()

Creates a predefined sequence of page references for the
simulation.

A fixed reference string ensures FIFO and LRU are tested
using the same page access pattern, producing consistent
and comparable results.
------------------------------------------------------------
*/
void generate_reference_string(int ref_string[], int length, int max_page_number) {
    int pattern[REF_STRING_LENGTH] = {
        1, 2, 3, 4, 1, 2, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3
    };
    for (int i = 0; i < length; i++) {
        ref_string[i] = ((pattern[i] - 1) % max_page_number) + 1;
    }
}


void print_frame_boxes(int frames[], int num_frames, int highlight_frame, const char *highlight_color) {
    printf("  ┌");
    for (int f = 0; f < num_frames; f++) printf(f < num_frames - 1 ? "────┬" : "────┐");
    printf("\n");

    printf("  │");
    for (int f = 0; f < num_frames; f++) {
        const char *color = (f == highlight_frame) ? highlight_color : "";
        const char *reset = (f == highlight_frame) ? RESET : "";
        if (frames[f] == -1)
            printf(" %s%2s%s │", color, "-", reset);
        else
            printf(" %s%2d%s │", color, frames[f], reset);
    }
    printf("\n");

    printf("  └");
    for (int f = 0; f < num_frames; f++) printf(f < num_frames - 1 ? "────┴" : "────┘");
    printf("\n");
}

/*
------------------------------------------------------------
run_fifo()

Simulates the First-In-First-Out (FIFO) page replacement
algorithm.

When memory becomes full, the page that entered memory first
is replaced by the newly requested page.
------------------------------------------------------------
*/
void run_fifo(int ref_string[], int length, int num_frames, int *out_faults, int *out_hits) {
    int frames[MAX_FRAMES];   // Array representing the contents of physical memory frames.
    for (int i = 0; i < num_frames; i++) frames[i] = -1;

    int queue[MAX_FRAMES];    // Queue used to maintain the order in which pages entered memory.
    int queue_front = 0, queue_size = 0;
    int faults = 0, hits = 0;    // Track page hits and page faults.

    printf("\n" BOLD CYAN "┌─────────────────────────────────────┐\n" RESET);
    printf(BOLD CYAN "│         FIFO PAGE REPLACEMENT        │\n" RESET);
    printf(BOLD CYAN "└─────────────────────────────────────┘\n\n" RESET);

    for (int i = 0; i < length; i++) {
        int page = ref_string[i];
        int found_frame = -1;

        for (int f = 0; f < num_frames; f++) {   // Search for the requested page in memory.   
            if (frames[f] == page) { found_frame = f; break; }
        }

        if (found_frame != -1) {
            hits++;
            printf(BOLD "Access %2d" RESET "  page " BOLD "%d" RESET "  " GREEN BOLD "HIT" RESET "\n",
                   i + 1, page);
            print_frame_boxes(frames, num_frames, found_frame, GREEN BOLD);
        } else {
            faults++;
            int evict_frame;
            if (queue_size < num_frames) {
                evict_frame = queue_size;
                queue_size++;
            } else {
                evict_frame = queue[queue_front];
                queue_front = (queue_front + 1) % num_frames;
            }

            int evicted_page = frames[evict_frame];
            frames[evict_frame] = page;
            queue[(queue_front + queue_size - 1) % num_frames] = evict_frame;

            printf(BOLD "Access %2d" RESET "  page " BOLD "%d" RESET "  " YELLOW BOLD "FAULT" RESET, i + 1, page);
            if (evicted_page != -1)
                printf(DIM "  (evicted page %d, arrived earliest)" RESET, evicted_page);
            printf("\n");
            print_frame_boxes(frames, num_frames, evict_frame, YELLOW BOLD);
        }
        printf("\n");
    }

    *out_faults = faults;
    *out_hits = hits;
}

/*
------------------------------------------------------------
run_lru()

Simulates the Least Recently Used (LRU) page replacement
algorithm.

When memory becomes full, the page that has not been used
for the longest time is replaced.
------------------------------------------------------------
*/
void run_lru(int ref_string[], int length, int num_frames, int *out_faults, int *out_hits) {
    int frames[MAX_FRAMES];
    // Stores the most recent access time for each frame.
    int last_used[MAX_FRAMES];\
    // Search for the requested page in memory.
    for (int i = 0; i < num_frames; i++) {
        frames[i] = -1;
        last_used[i] = -1;
    }

    int faults = 0, hits = 0;

    printf("\n" BOLD CYAN "┌─────────────────────────────────────┐\n" RESET);
    printf(BOLD CYAN "│         LRU PAGE REPLACEMENT         │\n" RESET);
    printf(BOLD CYAN "└─────────────────────────────────────┘\n\n" RESET);

    for (int i = 0; i < length; i++) {
        int page = ref_string[i];
        int found_frame = -1;

        for (int f = 0; f < num_frames; f++) {
            if (frames[f] == page) { found_frame = f; break; }
        }

        if (found_frame != -1) {
            hits++;
            // Update the page's most recent access time.
            last_used[found_frame] = i;
            printf(BOLD "Access %2d" RESET "  page " BOLD "%d" RESET "  " GREEN BOLD "HIT" RESET "\n",
                   i + 1, page);
            print_frame_boxes(frames, num_frames, found_frame, GREEN BOLD);
        } else {
            faults++;
            int evict_frame = -1;

            // Look for an empty frame before replacing any page.
            for (int f = 0; f < num_frames; f++) {
                if (frames[f] == -1) { evict_frame = f; break; }
            }
            // Memory is full, replace the least recently used page.
            if (evict_frame == -1) {
                int oldest_time = last_used[0];
                evict_frame = 0;
                for (int f = 1; f < num_frames; f++) {
                    if (last_used[f] < oldest_time) {
                        oldest_time = last_used[f];
                        evict_frame = f;
                    }
                }
            }

            int evicted_page = frames[evict_frame];
            frames[evict_frame] = page;
            last_used[evict_frame] = i;    // Record the current access time.

            printf(BOLD "Access %2d" RESET "  page " BOLD "%d" RESET "  " YELLOW BOLD "FAULT" RESET, i + 1, page);
            if (evicted_page != -1)
                printf(DIM "  (evicted page %d, least recently used)" RESET, evicted_page);
            printf("\n");
            print_frame_boxes(frames, num_frames, evict_frame, YELLOW BOLD);
        }
        printf("\n");
    }

    *out_faults = faults;
    *out_hits = hits;
}

/*
------------------------------------------------------------
print_summary_table()

Displays a summary comparing FIFO and LRU based on the
number of page hits, page faults, and their ratios.
------------------------------------------------------------
*/
void print_summary_table(int fifo_hits, int fifo_faults, int lru_hits, int lru_faults, int total) {
    printf(BOLD CYAN "┌───────────┬────────┬──────────┬───────────┬────────────┐\n" RESET);
    printf(BOLD CYAN "│ %-9s │ %-6s │ %-8s │ %-9s │ %-10s │\n" RESET,
           "Algorithm", "Hits", "Faults", "Hit Ratio", "Miss Ratio");
    printf(BOLD CYAN "├───────────┼────────┼──────────┼───────────┼────────────┤\n" RESET);
    printf("│ %-9s │ %-6d │ %-8d │ %-9.2f │ %-10.2f │\n",
           "FIFO", fifo_hits, fifo_faults,
           (float)fifo_hits / total, (float)fifo_faults / total);
    printf("│ %-9s │ %-6d │ %-8d │ %-9.2f │ %-10.2f │\n",
           "LRU", lru_hits, lru_faults,
           (float)lru_hits / total, (float)lru_faults / total);
    printf(BOLD CYAN "└───────────┴────────┴──────────┴───────────┴────────────┘\n" RESET);
}

int main(int argc, char *argv[]) {
    // Read the number of frames and page size from
    // the command-line arguments.
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <num_frames> <page_size_bytes>\n", argv[0]);
        fprintf(stderr, "Example: %s 4 256\n", argv[0]);
        return 1;
    }

    int num_frames = atoi(argv[1]);    // Convert command-line arguments to integers.
    int page_size  = atoi(argv[2]);

    if (num_frames <= 0 || num_frames > MAX_FRAMES) {    // Validate the user input.
        fprintf(stderr, "Error: num_frames must be between 1 and %d\n", MAX_FRAMES);
        return 1;
    }
    if (page_size <= 0) {
        fprintf(stderr, "Error: page_size_bytes must be positive\n");
        return 1;
    }

    printf(BOLD CYAN "=========================================\n" RESET);
    printf(BOLD CYAN "   VIRTUAL MEMORY MANAGEMENT SIMULATOR\n" RESET);
    printf(BOLD CYAN "=========================================\n" RESET);
    printf("Frames     : " BOLD "%d\n" RESET, num_frames);
    printf("Page size  : " BOLD "%d bytes\n" RESET, page_size);

    int ref_string[REF_STRING_LENGTH];    // Generate the page reference string used by both algorithms.
    generate_reference_string(ref_string, REF_STRING_LENGTH, 5);

    printf("\nReference string: ");
    for (int i = 0; i < REF_STRING_LENGTH; i++) printf(BOLD "%d " RESET, ref_string[i]);
    printf("\n");

    printf("\n" DIM "Legend:  " GREEN BOLD "green" RESET DIM " = hit    " YELLOW BOLD "yellow" RESET DIM " = page just loaded / evicted slot" RESET "\n");

    int fifo_faults, fifo_hits;
    // Execute the FIFO page replacement simulation.
    run_fifo(ref_string, REF_STRING_LENGTH, num_frames, &fifo_faults, &fifo_hits);

    int lru_faults, lru_hits;
    // Execute the LRU page replacement simulation.
    run_lru(ref_string, REF_STRING_LENGTH, num_frames, &lru_faults, &lru_hits);

    printf(BOLD CYAN "\n=========================================\n" RESET);
    printf(BOLD CYAN "           COMPARISON SUMMARY\n" RESET);
    printf(BOLD CYAN "=========================================\n\n" RESET);
    print_summary_table(fifo_hits, fifo_faults, lru_hits, lru_faults, REF_STRING_LENGTH);

    return 0;
}