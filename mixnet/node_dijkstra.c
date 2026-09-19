#include "node_internal.h"

#include <stdlib.h>

/* Only allocated for one recomputation; none of these fields persist in state. */
struct dijkstra_vertex {
    uint64_t cost;
    mixnet_address parent;
    bool in_pool;
    bool processed;
};

static size_t dijkstra_address_capacity(
    const struct mixnet_node_config *const c,
    const struct node_state *const state) {

    size_t capacity = (size_t) c->node_addr + 1;
    if (state->lsa_records_capacity > capacity) {
        capacity = state->lsa_records_capacity;
    }
    for (uint16_t port = 0; port < c->num_neighbors; port++) {
        const mixnet_address address = state->neighbor_records[port].neighbor_address;
        if ((address != INVALID_MIXADDR) && ((size_t) address >= capacity)) {
            capacity = (size_t) address + 1;
        }
    }
    /* A neighbor can be known before its own LSA has arrived. */
    for (size_t address = 0; address < state->lsa_records_capacity; address++) {
        const mixnet_packet_lsa *const lsa = state->lsa_records[address];
        if (lsa == NULL) {
            continue;
        }
        for (uint16_t i = 0; i < lsa->neighbor_count; i++) {
            const mixnet_address neighbor = lsa->links[i].neighbor_mixaddr;
            if ((neighbor != INVALID_MIXADDR) && ((size_t) neighbor >= capacity)) {
                capacity = (size_t) neighbor + 1;
            }
        }
    }
    return capacity;
}

static mixnet_address dijkstra_pop_minimum(
    struct dijkstra_vertex *const vertices,
    const size_t capacity,
    unsigned int *const random_seed) {

    mixnet_address selected = INVALID_MIXADDR;
    uint64_t minimum_cost = UINT64_MAX;
    unsigned int ties = 0;
    for (size_t address = 0; address < capacity; address++) {
        if (!vertices[address].in_pool) {
            continue;
        }
        if (vertices[address].cost < minimum_cost) {
            minimum_cost = vertices[address].cost;
            selected = (mixnet_address) address;
            ties = 1;
        } else if (vertices[address].cost == minimum_cost) {
            ties++;
            /* Deliberately random among minimum-cost candidates, per the
             * student's decision. Do not add a first-hop priority here. */
            if ((unsigned int) rand_r(random_seed) % ties == 0) {
                selected = (mixnet_address) address;
            }
        }
    }
    if (selected != INVALID_MIXADDR) {
        vertices[selected].in_pool = false;
        vertices[selected].processed = true;
    }
    return selected;
}

static mixnet_address dijkstra_first_hop(
    const struct dijkstra_vertex *const vertices,
    const size_t capacity,
    const mixnet_address source,
    mixnet_address node) {

    for (size_t steps = 0; steps < capacity; steps++) {
        if ((node == INVALID_MIXADDR) || ((size_t) node >= capacity)) {
            return INVALID_MIXADDR;
        }
        if (vertices[node].parent == source) {
            return node;
        }
        node = vertices[node].parent;
    }
    return INVALID_MIXADDR;
}

static bool dijkstra_update_neighbor(
    struct dijkstra_vertex *const vertices,
    const size_t capacity,
    const mixnet_address source,
    const mixnet_address current,
    const mixnet_address neighbor,
    const uint16_t link_cost) {

    if (neighbor == INVALID_MIXADDR) {
        return true; // Local neighbor discovery may still be incomplete.
    }
    if ((size_t) neighbor >= capacity) {
        return false;
    }
    struct dijkstra_vertex *const candidate = &vertices[neighbor];
    if (candidate->processed) {
        return true; // Finalized nodes are never reopened in this design.
    }
    const uint64_t new_cost = vertices[current].cost + (uint64_t) link_cost;
    bool replace = !candidate->in_pool || (new_cost < candidate->cost);
    if (candidate->in_pool && (new_cost == candidate->cost)) {
        const mixnet_address new_first_hop = current == source ? neighbor :
            dijkstra_first_hop(vertices, capacity, source, current);
        const mixnet_address old_first_hop =
            dijkstra_first_hop(vertices, capacity, source, neighbor);
        if ((new_first_hop == INVALID_MIXADDR) ||
            (old_first_hop == INVALID_MIXADDR)) {
            return false;
        }
        replace = new_first_hop < old_first_hop;
    }
    if (replace) {
        candidate->cost = new_cost;
        candidate->parent = current;
        candidate->in_pool = true;
    }
    return true;
}

static bool dijkstra_store_results(
    struct node_state *const result,
    const struct dijkstra_vertex *const vertices,
    const size_t capacity,
    const mixnet_address source) {

    mixnet_address *const path = malloc(capacity * sizeof(*path));
    if (path == NULL) {
        return false;
    }
    for (size_t address = 0; address < capacity; address++) {
        if (!vertices[address].processed) {
            continue;
        }
        size_t count = 0;
        mixnet_address node = (mixnet_address) address;
        for (;;) {
            if ((node == INVALID_MIXADDR) || ((size_t) node >= capacity) ||
                (count == capacity)) {
                free(path);
                return false;
            }
            path[count++] = node;
            if (node == source) {
                break;
            }
            node = vertices[node].parent;
        }
        /* The parent walk produced destination-to-source order. */
        for (size_t i = 0; i < count / 2; i++) {
            const mixnet_address temporary = path[i];
            path[i] = path[count - 1 - i];
            path[count - 1 - i] = temporary;
        }
        if (!store_route_path(result, (mixnet_address) address,
                               vertices[address].cost, path, count)) {
            free(path);
            return false;
        }
    }
    free(path);
    return true;
}

bool recompute_shortest_paths(
    const struct mixnet_node_config *const c, // to get link costs and own address
    struct node_state *const state) {

    const size_t capacity = dijkstra_address_capacity(c, state);
    if ((capacity == 0) || (capacity > (size_t) INVALID_MIXADDR)) {
        return false;
    }
    struct dijkstra_vertex *const vertices = calloc(capacity, sizeof(*vertices));
    if (vertices == NULL) {
        return false;
    }
    uint64_t now_ms;
    if (!get_monotonic_time_ms(&now_ms)) {
        free(vertices);
        return false;
    }
    unsigned int random_seed = (unsigned int) now_ms ^
        (unsigned int) (now_ms >> 32) ^ (unsigned int) c->node_addr;
    for (size_t address = 0; address < capacity; address++) {
        vertices[address].cost = UINT64_MAX;
        vertices[address].parent = INVALID_MIXADDR;
    }
    vertices[c->node_addr].cost = 0;
    vertices[c->node_addr].in_pool = true;

    /* This temporary state owns only the newly computed routing table. */
    struct node_state result = {0};
    bool succeeded = true;
    for (;;) {
        const mixnet_address current =
            dijkstra_pop_minimum(vertices, capacity, &random_seed);
        if (current == INVALID_MIXADDR) {
            break; // The pool is empty, including during partial discovery.
        }
        if (current == c->node_addr) {
            /* Own links come from local discovery, without waiting for our
             * own LSA to return. Routing can use all physical links. */
            for (uint16_t port = 0; port < c->num_neighbors; port++) {
                if (!dijkstra_update_neighbor(vertices, capacity, c->node_addr,
                        current, state->neighbor_records[port].neighbor_address,
                        c->link_costs[port])) {
                    succeeded = false;
                    break;
                }
            }
        } else if ((size_t) current < state->lsa_records_capacity) {
            const mixnet_packet_lsa *const lsa = state->lsa_records[current];
            if (lsa != NULL) {
                for (uint16_t i = 0; i < lsa->neighbor_count; i++) {
                    if (!dijkstra_update_neighbor(vertices, capacity, c->node_addr,
                            current, lsa->links[i].neighbor_mixaddr,
                            lsa->links[i].cost)) {
                        succeeded = false;
                        break;
                    }
                }
            }
        }
        if (!succeeded) {
            break;
        }
    }
    /* First check: did the Dijkstra computation succeed?
     * Building the full paths allocates memory and can still fail, so this
     * call updates succeeded to include the result of that second stage. */
    if (succeeded) {
        succeeded = dijkstra_store_results(&result, vertices, capacity, c->node_addr);
    }
    free(vertices);
    /* Second check: did BOTH computation and full-path storage succeed?
     * Publish the new table only then; otherwise free the partial result
     * and keep the node's previous routing table. */
    if (succeeded) {
        clear_route_paths(state);
        state->routes = result.routes;
        state->routes_capacity = result.routes_capacity;
        return true;
    } else {
        clear_route_paths(&result);
        return false;
    }
}
