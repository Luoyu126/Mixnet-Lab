/**
 * Copyright (C) 2023 Carnegie Mellon University
 *
 * This file is part of the Mixnet course project developed for
 * the Computer Networks course (15-441/641) taught at Carnegie
 * Mellon University.
 *
 * No part of the Mixnet project may be copied and/or distributed
 * without the express permission of the 15-441/641 course staff.
 */
#include "node_internal.h"

#include "connection.h"

#include <stdlib.h>
#include <time.h>

struct root_candidate {
    mixnet_address root_address;
    uint16_t root_hops;
    mixnet_address neighbor_address;
    uint16_t root_port;
    uint64_t last_update_time_ms;
};

bool get_monotonic_time_ms(uint64_t *const time_ms) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return false;
    }

    *time_ms = ((uint64_t) now.tv_sec * UINT64_C(1000)) +
               ((uint64_t) now.tv_nsec / UINT64_C(1000000));
    return true;
}

static mixnet_packet *create_stp_packet(
    const struct mixnet_node_config *const c,
    const struct node_state *const state) {

    const uint16_t packet_size = sizeof(mixnet_packet) +
                                 sizeof(mixnet_packet_stp);
    mixnet_packet *const packet = calloc(1, packet_size);
    if (packet == NULL) {
        return NULL;
    }

    packet->total_size = packet_size;
    packet->type = PACKET_TYPE_STP;

    mixnet_packet_stp *const stp =
        (mixnet_packet_stp *) packet->payload;
    stp->root_address = state->best_root.root_address;
    stp->path_length = state->best_root.root_hops;
    stp->node_address = c->node_addr;

    return packet;
}

static bool send_until_success(
    void *const handle,
    const uint8_t port,
    mixnet_packet *const packet) {

    int sent;
    do {
        sent = mixnet_send(handle, port, packet);
    } while (sent == 0);

    if (sent == 1) {
        return true;
    }

    free(packet);
    return false;
}

static bool send_stp_to_neighbors(
    void *const handle,
    const struct mixnet_node_config *const c,
    const struct node_state *const state,
    const uint16_t excluded_port) {

    for (uint16_t port = 0; port < c->num_neighbors; port++) {
        if (port == excluded_port) {
            continue;
        }

        mixnet_packet *const packet = create_stp_packet(c, state);
        if (packet == NULL) {
            return false;
        }

        if (!send_until_success(handle, (uint8_t) port, packet)) {
            return false;
        }
    }

    return true;
}

static bool root_candidate_is_better(
    const struct root_candidate *const candidate,
    const struct root_candidate *const current_best) {

    if (candidate->root_address != current_best->root_address) {
        return candidate->root_address < current_best->root_address;
    }

    if (candidate->root_hops != current_best->root_hops) {
        return candidate->root_hops < current_best->root_hops;
    }

    if (candidate->neighbor_address != current_best->neighbor_address) {
        return candidate->neighbor_address < current_best->neighbor_address;
    }

    return candidate->root_port < current_best->root_port;
}

/*
 * It may seem sufficient to compare only the newly updated port against the
 * previous best candidate. However, neighbor advertisements are not
 * guaranteed to improve monotonically: after a root path expires or a link
 * fails, the neighbor that supplied the previous best route may advertise a
 * larger root address or a longer path. In that case, the cached best no
 * longer represents any current candidate. Rechecking the node itself and
 * every valid neighbor record ensures that another neighbor, or this node,
 * can become the new best candidate.
 */
static struct root_candidate select_best_root_candidate(
    const struct mixnet_node_config *const c,
    const struct node_state *const state,
    const uint64_t current_time_ms) {

    struct root_candidate best = {
        .root_address = c->node_addr,
        .root_hops = 0,
        .neighbor_address = c->node_addr,
        .root_port = UINT16_MAX,
        .last_update_time_ms = current_time_ms,
    };

    for (uint16_t port = 0; port < c->num_neighbors; port++) {
        const struct neighbor_record *const record =
            &state->neighbor_records[port];
        if (!record->advertisement_valid) {
            continue;
        }

        const struct root_candidate candidate = {
            .root_address = record->advertised_root,
            .root_hops = (uint16_t) (record->advertised_hops + 1),
            .neighbor_address = record->neighbor_address,
            .root_port = port,
            .last_update_time_ms = record->last_update_time_ms,
        };

        if (root_candidate_is_better(&candidate, &best)) {
            best = candidate;
        }
    }

    return best;
}

static bool stp_packet_is_valid(
    const struct mixnet_node_config *const c,
    const struct node_state *const state,
    const uint8_t port,
    const mixnet_packet *const packet) {

    const uint16_t expected_size = sizeof(mixnet_packet) +
                                   sizeof(mixnet_packet_stp);
    if ((port >= c->num_neighbors) ||
        (packet->type != PACKET_TYPE_STP) ||
        (packet->total_size != expected_size)) {
        return false;
    }

    const mixnet_packet_stp *const stp =
        (const mixnet_packet_stp *) packet->payload;
    if ((stp->root_address == INVALID_MIXADDR) ||
        (stp->node_address == INVALID_MIXADDR) ||
        (stp->path_length == UINT16_MAX)) {
        return false;
    }

    const mixnet_address known_neighbor =
        state->neighbor_records[port].neighbor_address;
    return (known_neighbor == INVALID_MIXADDR) ||
           (known_neighbor == stp->node_address);
}

bool send_initial_stp(
    void *const handle,
    const struct mixnet_node_config *const c,
    struct node_state *const state) {

    if (!send_stp_to_neighbors(handle, c, state, UINT16_MAX)) {
        return false;
    }

    return get_monotonic_time_ms(&state->best_root.last_hello_time_ms);
}

enum node_timer_result handle_expired_timer(
    void *const handle,
    const struct mixnet_node_config *const c,
    struct node_state *const state,
    bool *const state_changed) {

    *state_changed = false;

    uint64_t current_time_ms;
    if (!get_monotonic_time_ms(&current_time_ms)) {
        return NODE_TIMER_ERROR;
    }

    const bool is_root = state->best_root.root_address == c->node_addr;
    const uint32_t interval_ms = is_root ? c->root_hello_interval_ms :
                                         c->reelection_interval_ms;
    if (current_time_ms - state->best_root.last_hello_time_ms < interval_ms) {
        return NODE_TIMER_IDLE;
    }

    if (!is_root) {
        /* Reelection changes the selected root even if no record is valid. */
        *state_changed = true;
        /* Retain neighbor identities, but stop using their old advertisements. */
        for (uint16_t port = 0; port < c->num_neighbors; port++) {
            state->neighbor_records[port].advertisement_valid = false;
        }
        state->best_root.root_address = c->node_addr;
        state->best_root.root_hops = 0;
        state->best_root.root_port = UINT16_MAX;
    }

    if (!send_stp_to_neighbors(handle, c, state, UINT16_MAX)) {
        return NODE_TIMER_ERROR;
    }

    /* Start the next hello interval after sending, including zero neighbors. */
    if (!get_monotonic_time_ms(&state->best_root.last_hello_time_ms)) {
        return NODE_TIMER_ERROR;
    }
    return NODE_TIMER_HANDLED;
}

bool handle_stp_packet(
    void *const handle,
    const struct mixnet_node_config *const c,
    struct node_state *const state,
    const uint8_t port,
    mixnet_packet *const packet,
    bool *const state_changed) {

    *state_changed = false;

    if (!stp_packet_is_valid(c, state, port, packet)) {
        free(packet);
        return true;
    }

    uint64_t current_time_ms;
    if (!get_monotonic_time_ms(&current_time_ms)) {
        free(packet);
        return false;
    }

    const mixnet_packet_stp *const stp =
        (const mixnet_packet_stp *) packet->payload;
    struct neighbor_record *const record = &state->neighbor_records[port];
    const bool neighbor_changed =
        (record->neighbor_address != stp->node_address) ||
        (record->advertised_root != stp->root_address) ||
        (record->advertised_hops != stp->path_length) ||
        !record->advertisement_valid;
    record->neighbor_address = stp->node_address;
    record->advertised_root = stp->root_address;
    record->advertised_hops = stp->path_length;
    record->last_update_time_ms = current_time_ms;
    record->advertisement_valid = true;

    const struct best_root previous_best = state->best_root;
    const struct root_candidate best_candidate =
        select_best_root_candidate(c, state, current_time_ms);

    state->best_root.root_address = best_candidate.root_address;
    state->best_root.root_port = best_candidate.root_port;
    state->best_root.root_hops = best_candidate.root_hops;

    const bool best_changed =
        (state->best_root.root_address != previous_best.root_address) ||
        (state->best_root.root_port != previous_best.root_port) ||
        (state->best_root.root_hops != previous_best.root_hops);
    *state_changed = neighbor_changed || best_changed;
    const bool received_current_root_hello =
        (state->best_root.root_port == port) &&
        (stp->root_address == state->best_root.root_address);

    if (state->best_root.root_port != UINT16_MAX) {
        state->best_root.last_hello_time_ms =
            best_candidate.last_update_time_ms;
    } else {
        state->best_root.last_hello_time_ms =
            previous_best.last_hello_time_ms;
    }

    if (received_current_root_hello) {
        state->best_root.last_hello_time_ms = current_time_ms;
    }

    bool succeeded = true;
    if (best_changed || received_current_root_hello) {
        /* Also advertise back to the parent after its hello so it can
         * relearn this neighbor's advertisement following reelection. */
        const uint16_t excluded_port =
            received_current_root_hello ? UINT16_MAX : port;
        succeeded = send_stp_to_neighbors(handle, c, state, excluded_port);
    }

    if (succeeded && best_changed &&
        (state->best_root.root_address == c->node_addr)) {
        state->best_root.last_hello_time_ms = current_time_ms;
    }

    free(packet);
    return succeeded;
}
