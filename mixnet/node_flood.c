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

enum stp_port_role {
    STP_PORT_UNKNOWN,
    STP_PORT_ROOT,
    STP_PORT_DESIGNATED,
    STP_PORT_BLOCKED,
};

static bool flood_packet_is_valid(
    const struct mixnet_node_config *const c,
    const uint8_t port,
    const mixnet_packet *const packet) {

    return (port <= c->num_neighbors) &&
           (packet->type == PACKET_TYPE_FLOOD) &&
           (packet->total_size == sizeof(mixnet_packet));
}

static bool local_stp_bid_is_better(
    const struct mixnet_node_config *const c,
    const struct node_state *const state,
    const struct neighbor_record *const neighbor) {

    if (state->best_root.root_address != neighbor->advertised_root) {
        return state->best_root.root_address < neighbor->advertised_root;
    }

    if (state->best_root.root_hops != neighbor->advertised_hops) {
        return state->best_root.root_hops < neighbor->advertised_hops;
    }

    return c->node_addr < neighbor->neighbor_address;
}

static enum stp_port_role get_stp_port_role(
    const struct mixnet_node_config *const c,
    const struct node_state *const state,
    const uint16_t port) {

    const struct neighbor_record *const neighbor =
        &state->neighbor_records[port];
    if (!neighbor->advertisement_valid) {
        return STP_PORT_UNKNOWN;
    }

    if (port == state->best_root.root_port) {
        return STP_PORT_ROOT;
    }

    if (local_stp_bid_is_better(c, state, neighbor)) {
        return STP_PORT_DESIGNATED;
    }

    return STP_PORT_BLOCKED;
}

static bool port_forwards_flood(const enum stp_port_role role) {
    return (role == STP_PORT_ROOT) || (role == STP_PORT_DESIGNATED);
}

bool stp_port_forwards_flood(
    const struct mixnet_node_config *const c,
    const struct node_state *const state,
    const uint16_t port) {

    return port_forwards_flood(get_stp_port_role(c, state, port));
}

static mixnet_packet *create_flood_packet(void) {
    mixnet_packet *const packet = calloc(1, sizeof(mixnet_packet));
    if (packet == NULL) {
        return NULL;
    }

    packet->total_size = sizeof(mixnet_packet);
    packet->type = PACKET_TYPE_FLOOD;
    return packet;
}

static bool send_flood_to_port(
    void *const handle,
    const uint8_t port) {

    mixnet_packet *const packet = create_flood_packet();
    if (packet == NULL) {
        return false;
    }

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

static bool send_flood_to_forwarding_neighbors(
    void *const handle,
    const struct mixnet_node_config *const c,
    const struct node_state *const state,
    const uint16_t excluded_port) {

    for (uint16_t port = 0; port < c->num_neighbors; port++) {
        if ((port == excluded_port) ||
            !stp_port_forwards_flood(c, state, port)) {
            continue;
        }

        if (!send_flood_to_port(handle, (uint8_t) port)) {
            return false;
        }
    }

    return true;
}

bool handle_flood_packet(
    void *const handle,
    const struct mixnet_node_config *const c,
    struct node_state *const state,
    const uint8_t port,
    mixnet_packet *const packet) {

    if (!flood_packet_is_valid(c, port, packet)) {
        free(packet);
        return true;
    }

    bool succeeded = true;
    if (port == c->num_neighbors) {
        succeeded = send_flood_to_forwarding_neighbors(
            handle, c, state, UINT16_MAX);
    } else if (stp_port_forwards_flood(c, state, port)) {
        succeeded = send_flood_to_port(handle, (uint8_t) c->num_neighbors);
        if (succeeded) {
            succeeded = send_flood_to_forwarding_neighbors(
                handle, c, state, port);
        }
    }

    free(packet);
    return succeeded;
}
