#include "node_internal.h"

#include <stdlib.h>

static const unsigned int MAX_RANDOM_REPETITIONS = 34;

mixnet_address *create_random_path(const struct route_record *route,
                                   size_t max_node_count,
                                   unsigned int *random_seed,
                                   size_t *node_count) {
    size_t begin, end, count;
    unsigned int repetitions;
    do {
        // Choose two distinct positions in the original full path.
        begin = (size_t) rand_r(random_seed) % route->node_count;
        end = (size_t) rand_r(random_seed) % (route->node_count - 1);
        if (end >= begin) {
            end++;
        }
        if (begin > end) {
            const size_t temporary = begin;
            begin = end;
            end = temporary;
        }
        repetitions = (unsigned int) rand_r(random_seed) %
            (MAX_RANDOM_REPETITIONS + 1);
        count = route->node_count + 2 * (end - begin) * repetitions;
        // Retry all choices if the proposed path cannot fit this packet.
        // Zero repetitions always fits because the caller checked the base.
    } while (count > max_node_count);

    mixnet_address *path = malloc(count * sizeof(*path));
    if (path == NULL) {
        return NULL;
    }
    size_t out = 0;
    for (size_t i = 0; i <= end; i++) {
        path[out++] = route->path[i];
    }
    for (unsigned int repeat = 0; repeat < repetitions; repeat++) {
        // Retrace the chosen segment, then walk forward over it again.
        for (size_t i = end; i > begin; i--) {
            path[out++] = route->path[i - 1];
        }
        for (size_t i = begin + 1; i <= end; i++) {
            path[out++] = route->path[i];
        }
    }
    for (size_t i = end + 1; i < route->node_count; i++) {
        path[out++] = route->path[i];
    }
    *node_count = count;
    return path;
}
