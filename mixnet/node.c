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
#include "node.h"

#include "connection.h"
#include "node_internal.h"
#include "packet.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * mixnet_node_config is defined in config.h (included through node.h).
 *
 *  +------------------------------------------------------+
 *  | node_addr                                            |
 *  |   This node's Mixnet address                         |
 *  +------------------------------------------------------+
 *  | num_neighbors = n                                    |
 *  |   Neighbor ports are 0 .. n - 1                     |
 *  |   User input/output port is n                        |
 *  +------------------------------------------------------+
 *  | root_hello_interval_ms                               |
 *  | reelection_interval_ms                               |
 *  |   CP1 timing configuration                           |
 *  +------------------------------------------------------+
 *  | do_random_routing                                    |
 *  | mixing_factor                                        |
 *  |   Routing/mixing configuration (used in CP2)         |
 *  +------------------------------------------------------+
 *  | link_costs                                           |
 *  |   Pointer to n costs: link_costs[i] belongs to       |
 *  |   neighbor port i; i is not a Mixnet address         |
 *  +------------------------------------------------------+
 */

static bool initialize_node_state(struct node_state *const state,
                                  const struct mixnet_node_config *const c) {
    state->neighbor_records = NULL;
    state->best_root.root_address = c->node_addr; // Initially, the node considers itself the root
    state->best_root.root_port = UINT16_MAX; // invalid port number, since the node is the root
    state->best_root.root_hops = 0;
    state->best_root.last_hello_time_ms = 0;
    state->stp_last_change_time_ms = 0;
    state->stp_quiet_elapsed_ms = 0;
    state->lsa_sent_in_quiet_period = false;
    state->lsa_last_send_time_ms = 0;
    state->lsa_records = NULL;
    state->lsa_records_capacity = 0;
    state->routes = NULL;
    state->routes_capacity = 0;
    state->last_ping_rtt_ms = 0;
    state->has_ping_rtt = false;
    state->random_route_seed = (unsigned int) c->node_addr;
    state->mix_count = 0;
    state->mix_buffer = calloc(c->mixing_factor, sizeof(*state->mix_buffer));
    if (state->mix_buffer == NULL) {
        return false;
    }

    if (c->num_neighbors == 0) {
        return true;
    }

    state->neighbor_records = calloc(c->num_neighbors,
                                     sizeof(*state->neighbor_records));
    if (state->neighbor_records == NULL) {
        release_mixing_buffer(state);
        return false;
    }

    /*
     * Pointer constness reference:
     *
     * struct neighbor_record *record;
     *     The pointer and the pointed-to record are both mutable.
     *
     * const struct neighbor_record *record;
     *     The pointer is mutable; the pointed-to record is const.
     *
     * struct neighbor_record *const record;
     *     The pointer is const; the pointed-to record is mutable.
     *
     * const struct neighbor_record *const record;
     *     The pointer and the pointed-to record are both const.
     */
    for (uint16_t port = 0; port < c->num_neighbors; port++) {
        struct neighbor_record *const record = &state->neighbor_records[port];
        record->neighbor_address = INVALID_MIXADDR;
        record->advertised_root = INVALID_MIXADDR;
        record->advertised_hops = UINT16_MAX;
    }

    return true;
}

static void release_node_state(struct node_state *const state) {
    release_mixing_buffer(state);
    clear_route_paths(state);
    for (size_t address = 0; address < state->lsa_records_capacity; address++) {
        free(state->lsa_records[address]);
    }
    free(state->lsa_records);
    state->lsa_records = NULL;
    state->lsa_records_capacity = 0;
    free(state->neighbor_records);
    state->neighbor_records = NULL; // defensive programming: avoid dangling pointer
}

/*
 * Pseudocode for the node's main event loop:
 *
 * Initialize node state.
 *
 * while keep_running:
 *     Check for and handle an expired timer event.
 *
 *     If no timer event was handled:
 *         Try to receive one packet and handle it according to its type.
 *
 *     After either event path, update the STP quiet-period clock.
 *     Non-time STP changes restart the quiet period.
 *     Check initial/periodic LSA sending here, while STP continues running.
 *
 * Release node state.
 */

void run_node(void *const handle, // opaque handle, keep this as the first argument to all mixnet_* functions
              volatile bool *const keep_running, // volatile means that the compiler should not optimize this variable away, since it may be modified by another thread
              const struct mixnet_node_config c) {

    struct node_state state;
    if (!initialize_node_state(&state, &c)) {
        return;
    }

    if (!send_initial_stp(handle, &c, &state)) {
        release_node_state(&state);
        return;
    }
    state.stp_last_change_time_ms = state.best_root.last_hello_time_ms;
    /* Both LSA intervals equal the configured root hello interval. */
    const uint64_t lsa_interval_ms = c.root_hello_interval_ms;

    while (*keep_running) {
        bool stp_changed = false;
        const enum node_timer_result timer_result =
            handle_expired_timer(handle, &c, &state, &stp_changed);
        if (timer_result == NODE_TIMER_ERROR) {
            break;
        }
        if (timer_result == NODE_TIMER_IDLE) {
            // Preserve timer priority: receive only if no timer was handled.
            uint8_t port = 0;
            mixnet_packet *packet = NULL;
            const int received = mixnet_recv(handle, &port, &packet);
            if ((received == 1) &&
                !handle_received_packet(handle, &c, &state, port, packet,
                                        &stp_changed)) {
                break;
            }
        }

        uint64_t current_time_ms;
        if (!get_monotonic_time_ms(&current_time_ms)) {
            break;
        }
        if (stp_changed) {
            state.stp_last_change_time_ms = current_time_ms;
        }
        state.stp_quiet_elapsed_ms =
            current_time_ms - state.stp_last_change_time_ms;

        if (!handle_lsa_send_timer(handle, &c, &state, stp_changed,
                                   current_time_ms, lsa_interval_ms,
                                   lsa_interval_ms)) {
            break;
        }
    }

    release_node_state(&state);
}
