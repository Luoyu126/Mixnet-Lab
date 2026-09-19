#include "node_internal.h"

#include <stdlib.h>
#include <string.h>

bool store_route_path(
    struct node_state *const state,
    const mixnet_address destination,
    const uint64_t total_cost,
    const mixnet_address *const path,
    const size_t node_count) {

    if ((destination == INVALID_MIXADDR) || (path == NULL) ||
        (node_count == 0) ||
        (node_count > (SIZE_MAX - sizeof(struct route_record)) / sizeof(*path))) {
        return false;
    }
    if (path[node_count - 1] != destination) {
        return false;
    }

    const size_t size = sizeof(struct route_record) + node_count * sizeof(*path);
    struct route_record *const copy = malloc(size);
    if (copy == NULL) {
        return false;
    }
    copy->total_cost = total_cost;
    copy->node_count = node_count;
    memcpy(copy->path, path, node_count * sizeof(*path));

    const size_t address = destination;
    if (address >= state->routes_capacity) {
        const size_t new_capacity = address + 1;
        struct route_record **const resized = realloc(
            state->routes, new_capacity * sizeof(*resized));
        if (resized == NULL) {
            free(copy);
            return false;
        }
        for (size_t i = state->routes_capacity; i < new_capacity; i++) {
            resized[i] = NULL;
        }
        state->routes = resized;
        state->routes_capacity = new_capacity;
    }
    free(state->routes[address]);
    state->routes[address] = copy;
    return true;
}

void clear_route_paths(struct node_state *const state) {
    for (size_t address = 0; address < state->routes_capacity; address++) {
        free(state->routes[address]);
    }
    free(state->routes);
    state->routes = NULL;
    state->routes_capacity = 0;
}
