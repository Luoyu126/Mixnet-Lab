#include "node_internal.h"

#include "connection.h"

#include <stdlib.h>
#include <string.h>

static bool lsa_packet_is_valid(
    const struct mixnet_node_config *const c,
    const uint8_t port,
    const mixnet_packet *const packet) {

    /* Check sizes before accessing the variable-length payload. */
    if ((port >= c->num_neighbors) ||
        (packet->type != PACKET_TYPE_LSA) ||
        (packet->total_size < sizeof(mixnet_packet) + sizeof(mixnet_packet_lsa)) ||
        (packet->total_size > MAX_MIXNET_PACKET_SIZE)) {
        return false;
    }
    const mixnet_packet_lsa *const lsa =
        (const mixnet_packet_lsa *) packet->payload;
    const size_t expected_size = sizeof(mixnet_packet) + sizeof(*lsa) +
        ((size_t) lsa->neighbor_count * sizeof(mixnet_lsa_link_params));
    if ((packet->total_size != expected_size) ||
        (lsa->node_address == INVALID_MIXADDR)) {
        return false;
    }
    for (uint16_t i = 0; i < lsa->neighbor_count; i++) {
        if (lsa->links[i].neighbor_mixaddr == INVALID_MIXADDR) {
            return false;
        }
    }
    return true;
}

static bool lsa_contents_equal(
    const mixnet_packet_lsa *const old,
    const mixnet_packet_lsa *const incoming) {

    if ((old->node_address != incoming->node_address) ||
        (old->neighbor_count != incoming->neighbor_count)) {
        return false;
    }
    /* Compare address/cost pairs independently of advertised order.
     * Counting occurrences also preserves repeated link entries. */
    for (uint16_t i = 0; i < old->neighbor_count; i++) {
        size_t old_count = 0;
        size_t incoming_count = 0;
        for (uint16_t j = 0; j < old->neighbor_count; j++) {
            if ((old->links[j].neighbor_mixaddr == old->links[i].neighbor_mixaddr) &&
                (old->links[j].cost == old->links[i].cost)) {
                old_count++;
            }
            if ((incoming->links[j].neighbor_mixaddr == old->links[i].neighbor_mixaddr) &&
                (incoming->links[j].cost == old->links[i].cost)) {
                incoming_count++;
            }
        }
        if (old_count != incoming_count) {
            return false;
        }
    }
    return true;
}

static bool store_received_lsa(
    struct node_state *const state,
    const mixnet_packet_lsa *const lsa,
    bool *const topology_changed) {

    *topology_changed = false;
    const size_t address = lsa->node_address;
    if ((address < state->lsa_records_capacity) &&
        (state->lsa_records[address] != NULL) &&
        lsa_contents_equal(state->lsa_records[address], lsa)) {
        return true;
    }

    const size_t size = sizeof(*lsa) +
        ((size_t) lsa->neighbor_count * sizeof(mixnet_lsa_link_params));
    mixnet_packet_lsa *const copy = malloc(size);
    if (copy == NULL) {
        return false;
    }
    memcpy(copy, lsa, size);

    if (address >= state->lsa_records_capacity) {
        const size_t new_capacity = address + 1;
        mixnet_packet_lsa **const resized = realloc(
            state->lsa_records, new_capacity * sizeof(*resized));
        if (resized == NULL) {
            free(copy);
            return false;
        }
        for (size_t i = state->lsa_records_capacity; i < new_capacity; i++) {
            resized[i] = NULL;
        }
        state->lsa_records = resized;
        state->lsa_records_capacity = new_capacity;
    }
    /* Replace only after allocation succeeds, preserving old data on failure. */
    free(state->lsa_records[address]);
    state->lsa_records[address] = copy;
    *topology_changed = true;
    return true;
}

static bool forward_received_lsa(
    void *const handle,
    const struct mixnet_node_config *const c,
    const struct node_state *const state,
    const uint8_t incoming_port,
    const mixnet_packet *const packet) {

    for (uint16_t port = 0; port < c->num_neighbors; port++) {
        if ((port == incoming_port) || !stp_port_forwards_flood(c, state, port)) {
            continue;
        }
        mixnet_packet *const copy = malloc(packet->total_size);
        if (copy == NULL) {
            return false;
        }
        memcpy(copy, packet, packet->total_size);
        int sent;
        do {
            sent = mixnet_send(handle, (uint8_t) port, copy);
        } while (sent == 0);
        if (sent != 1) {
            free(copy);
            return false;
        }
    }
    return true;
}

bool handle_lsa_packet(
    void *const handle,
    const struct mixnet_node_config *const c,
    struct node_state *const state,
    const uint8_t port,
    mixnet_packet *const packet) {

    if (packet == NULL) {
        return false;
    }
    /* Apply the existing CP1 incoming tree-port rule to LSA flooding too. */
    if (!lsa_packet_is_valid(c, port, packet) ||
        !stp_port_forwards_flood(c, state, port)) {
        free(packet);
        return true;
    }

    bool topology_changed;
    if (!store_received_lsa(state,
                            (const mixnet_packet_lsa *) packet->payload,
                            &topology_changed)) {
        free(packet);
        return false;
    }
    if (topology_changed && !recompute_shortest_paths(c, state)) {
        free(packet);
        return false;
    }
    /* Unchanged advertisements still propagate; LSA never goes to the user. */
    const bool succeeded = forward_received_lsa(handle, c, state, port, packet);
    free(packet);
    return succeeded;
}

static bool all_neighbor_addresses_known(
    const struct mixnet_node_config *const c,
    const struct node_state *const state) {

    for (uint16_t port = 0; port < c->num_neighbors; port++) {
        if (state->neighbor_records[port].neighbor_address == INVALID_MIXADDR) {
            return false;
        }
    }
    return true;
}

static mixnet_packet *create_local_lsa_packet(
    const struct mixnet_node_config *const c,
    const struct node_state *const state) {

    const size_t size = sizeof(mixnet_packet) + sizeof(mixnet_packet_lsa) +
        ((size_t) c->num_neighbors * sizeof(mixnet_lsa_link_params));
    if ((size > MAX_MIXNET_PACKET_SIZE) ||
        ((c->num_neighbors > 0) && (c->link_costs == NULL))) {
        return NULL;
    }

    mixnet_packet *const packet = calloc(1, size);
    if (packet == NULL) {
        return NULL;
    }
    packet->total_size = (uint16_t) size;
    packet->type = PACKET_TYPE_LSA;
    mixnet_packet_lsa *const lsa = (mixnet_packet_lsa *) packet->payload;
    lsa->node_address = c->node_addr;
    lsa->neighbor_count = c->num_neighbors;
    /* Advertise every physical neighbor, including blocked tree ports. */
    for (uint16_t port = 0; port < c->num_neighbors; port++) {
        lsa->links[port].neighbor_mixaddr =
            state->neighbor_records[port].neighbor_address;
        lsa->links[port].cost = c->link_costs[port];
    }
    return packet;
}

static bool send_local_lsa(
    void *const handle,
    const struct mixnet_node_config *const c,
    const struct node_state *const state) {

    for (uint16_t port = 0; port < c->num_neighbors; port++) {
        if (!stp_port_forwards_flood(c, state, port)) {
            continue;
        }
        /* Each successful send transfers ownership of its own allocation. */
        mixnet_packet *const packet = create_local_lsa_packet(c, state);
        if (packet == NULL) {
            return false;
        }
        int sent;
        do {
            sent = mixnet_send(handle, (uint8_t) port, packet);
        } while (sent == 0);
        if (sent != 1) {
            free(packet);
            return false;
        }
    }
    return true;
}

bool handle_lsa_send_timer(
    void *const handle,
    const struct mixnet_node_config *const c,
    struct node_state *const state,
    const bool stp_changed,
    const uint64_t current_time_ms,
    const uint64_t quiet_interval_ms,
    const uint64_t repeat_interval_ms) {

    if (stp_changed) {
        state->lsa_sent_in_quiet_period = false;
    }
    if (!all_neighbor_addresses_known(c, state) ||
        (state->stp_quiet_elapsed_ms < quiet_interval_ms)) {
        return true;
    }
    if (state->lsa_sent_in_quiet_period &&
        (current_time_ms - state->lsa_last_send_time_ms < repeat_interval_ms)) {
        return true;
    }
    /* Also refresh from our own discovered links at the start of a quiet
     * period: an unchanged remote LSA would not trigger that computation.
     * This initializes the self-route even for a node with no neighbors. */
    if (!state->lsa_sent_in_quiet_period && !recompute_shortest_paths(c, state)) {
        return false;
    }
    if (!send_local_lsa(handle, c, state)) {
        return false;
    }
    /* Measure the next interval from completion, like the STP hello timer. */
    if (!get_monotonic_time_ms(&state->lsa_last_send_time_ms)) {
        return false;
    }
    state->lsa_sent_in_quiet_period = true;
    return true;
}
