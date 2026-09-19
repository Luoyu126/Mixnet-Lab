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

#include <stdlib.h>

bool handle_received_packet(
    void *const handle,
    const struct mixnet_node_config *const c,
    struct node_state *const state,
    const uint8_t port,
    mixnet_packet *const packet,
    bool *const state_changed) {

    *state_changed = false;

    if (packet == NULL) {
        return false;
    }

    switch (packet->type) {
    case PACKET_TYPE_STP:
        return handle_stp_packet(handle, c, state, port, packet, state_changed);
    case PACKET_TYPE_FLOOD:
        return handle_flood_packet(handle, c, state, port, packet);
    case PACKET_TYPE_LSA:
        return handle_lsa_packet(handle, c, state, port, packet);
    case PACKET_TYPE_DATA:
    case PACKET_TYPE_PING:
        return handle_routed_packet(handle, c, state, port, packet);
    default:
        /* Unknown packet type. */
        free(packet);
        return true;
    }
}
