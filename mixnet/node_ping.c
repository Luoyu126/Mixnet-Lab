#include "node_internal.h"

#include <stdlib.h>
#include <string.h>

static mixnet_packet_ping *ping_payload(mixnet_packet *packet) {
    mixnet_packet_routing_header *rh =
        (mixnet_packet_routing_header *) packet->payload;
    return (mixnet_packet_ping *) (rh->route + rh->route_length);
}

/* Called only for a user allocation with an empty route and no PING body. */
bool initialize_ping_request(mixnet_packet *packet) {
    uint64_t now_ms;
    if (!get_monotonic_time_ms(&now_ms)) {
        return false;
    }
    mixnet_packet_ping *ping = ping_payload(packet);
    memset(ping, 0, sizeof(*ping));
    ping->is_request = true;
    ping->send_time = now_ms;
    packet->total_size += sizeof(*ping);
    return true;
}

bool handle_ping_destination(void *handle, const struct mixnet_node_config *c,
                              struct node_state *state, mixnet_packet *packet) {
    mixnet_packet_ping *ping = ping_payload(packet);
    if (!ping->is_request) {
        uint64_t now_ms;
        if (!get_monotonic_time_ms(&now_ms)) {
            free(packet);
            return false;
        }
        /* Keep the original send_time in the delivered response. The handout
         * defines no RTT field or print format; retain the latest sample here. */
        state->last_ping_rtt_ms = now_ms - ping->send_time;
        state->has_ping_rtt = true;
        return send_routed_packet(handle, (uint8_t) c->num_neighbors, packet);
    }

    /* User delivery transfers ownership: create the reply before that send. */
    mixnet_packet *reply = malloc(packet->total_size);
    if (reply == NULL) {
        free(packet);
        return false;
    }
    memcpy(reply, packet, packet->total_size);
    mixnet_packet_routing_header *rh =
        (mixnet_packet_routing_header *) reply->payload;
    const mixnet_address original_source = rh->src_address;
    rh->src_address = rh->dst_address;
    rh->dst_address = original_source;
    for (uint16_t i = 0; i < rh->route_length / 2; i++) {
        const mixnet_address temporary = rh->route[i];
        rh->route[i] = rh->route[rh->route_length - 1 - i];
        rh->route[rh->route_length - 1 - i] = temporary;
    }
    rh->hop_index = 0;
    ping_payload(reply)->is_request = false;

    if (!send_routed_packet(handle, (uint8_t) c->num_neighbors, packet)) {
        free(reply);
        return false;
    }
    if ((rh->route_length == 0) && (rh->dst_address == c->node_addr)) {
        // A self-ping completes locally; the response branch cannot reply again.
        return handle_ping_destination(handle, c, state, reply);
    }
    return forward_routed_packet(handle, c, state, reply);
}
