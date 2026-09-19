#include "node_internal.h"
#include "connection.h"

#include <stdlib.h>
#include <string.h>

/* Consumes packet on both success and failure, like the CP1 send helpers. */
bool send_routed_packet(void *handle, uint8_t port, mixnet_packet *packet) {
    int sent;
    do {
        sent = mixnet_send(handle, port, packet);
    } while (sent == 0);
    if (sent == 1) {
        return true;
    } else {
        free(packet);
        return false;
    }
}

/* User packets have a MAX_MIXNET_PACKET_SIZE allocation, but total_size
 * describes only the header and actual data. Insert the route in place. */
static bool fill_source_route(const struct mixnet_node_config *c,
                            struct node_state *state,
                            mixnet_packet *packet) {
    mixnet_packet_routing_header *rh =
        (mixnet_packet_routing_header *) packet->payload;
    if (rh->route_length != 0) {
        return false;
    }
    rh->src_address = c->node_addr;
    rh->hop_index = 0;
    if (rh->dst_address == c->node_addr) {
        return true;
    }
    if ((rh->dst_address >= state->routes_capacity) ||
        (state->routes[rh->dst_address] == NULL)) {
        return false;
    }
    const struct route_record *route = state->routes[rh->dst_address];
    size_t max_route_length =
        (MAX_MIXNET_PACKET_SIZE - packet->total_size) / sizeof(mixnet_address);
    if (max_route_length > MAX_MIXNET_ROUTE_LENGTH) {
        max_route_length = MAX_MIXNET_ROUTE_LENGTH;
    }
    if (route->node_count - 2 > max_route_length) {
        return false;
    }
    size_t node_count = route->node_count;
    const mixnet_address *path = route->path;
    mixnet_address *random_path = NULL;
    if (c->do_random_routing) {
        random_path = create_random_path(route, max_route_length + 2,
                                          &state->random_route_seed, &node_count);
        if (random_path == NULL) {
            return false;
        }
        path = random_path;
    }
    const size_t route_length = node_count - 2;
    const size_t route_bytes = route_length * sizeof(mixnet_address);
    const size_t data_size = packet->total_size - sizeof(*packet) - sizeof(*rh);
    /* Move DATA or the PING payload before writing route addresses. */
    memmove((char *) rh->route + route_bytes, rh->route, data_size);
    memcpy(rh->route, path + 1, route_bytes);
    free(random_path);
    rh->route_length = (uint16_t) route_length;
    packet->total_size += (uint16_t) route_bytes;
    return true;
}

bool handle_routed_packet(void *handle, const struct mixnet_node_config *c,
                         struct node_state *state, uint8_t port,
                         mixnet_packet *packet) {
    /* Validate packet lengths before reading the header or route array. */
    if ((port > c->num_neighbors) ||
        (packet->total_size < sizeof(*packet) + sizeof(mixnet_packet_routing_header)) ||
        (packet->total_size > MAX_MIXNET_PACKET_SIZE)) {
        free(packet);
        return true;
    }
    mixnet_packet_routing_header *rh =
        (mixnet_packet_routing_header *) packet->payload;
    const size_t header_size = sizeof(*packet) + sizeof(*rh) +
        (size_t) rh->route_length * sizeof(mixnet_address);
    if ((rh->route_length > MAX_MIXNET_ROUTE_LENGTH) ||
        (header_size > packet->total_size) ||
        (rh->dst_address == INVALID_MIXADDR)) {
        free(packet);
        return true;
    }

    if (port == c->num_neighbors) {
        // Source: look up the full path and encode only intermediate nodes.
        if (packet->type == PACKET_TYPE_PING) {
            // The framework injects PING with only an empty routing header.
            if ((rh->route_length != 0) ||
                (packet->total_size != sizeof(*packet) + sizeof(*rh))) {
                free(packet);
                return true;
            }
            if (!initialize_ping_request(packet)) {
                free(packet);
                return false;
            }
        }
        if (!fill_source_route(c, state, packet)) {
            free(packet);
            return true;
        }
    } else {
        if ((packet->type == PACKET_TYPE_PING) &&
            (packet->total_size != header_size + sizeof(mixnet_packet_ping))) {
            free(packet);
            return true;
        }
        if (rh->hop_index < rh->route_length) {
            // Transit: hop_index identifies this occurrence of the current node.
            if (rh->route[rh->hop_index] != c->node_addr) {
                free(packet);
                return true;
            }
            rh->hop_index++;
        } else if ((rh->hop_index != rh->route_length) ||
                   (rh->dst_address != c->node_addr)) {
            free(packet);
            return true;
        }
    }

    // Deliver only at the end of the route, including source-to-self traffic.
    if ((rh->hop_index == rh->route_length) &&
        (rh->dst_address == c->node_addr)) {
        if (packet->type == PACKET_TYPE_PING) {
            return handle_ping_destination(handle, c, state, packet);
        }
        return send_routed_packet(handle, (uint8_t) c->num_neighbors, packet);
    }
    return forward_routed_packet(handle, c, state, packet);
}

/* hop_index already points to the next intermediate node, or to the end. */
bool forward_routed_packet(void *handle, const struct mixnet_node_config *c,
                           struct node_state *state, mixnet_packet *packet) {
    const mixnet_packet_routing_header *rh =
        (const mixnet_packet_routing_header *) packet->payload;
    const mixnet_address next = rh->hop_index < rh->route_length ?
        rh->route[rh->hop_index] : rh->dst_address;
    for (uint16_t neighbor_port = 0; neighbor_port < c->num_neighbors; neighbor_port++) {
        if (state->neighbor_records[neighbor_port].neighbor_address == next) {
            // Source-routed traffic can use any physical neighbor link.
            return enqueue_mixed_packet(handle, c, state,
                                         (uint8_t) neighbor_port, packet);
        }
    }
    free(packet); // No local link matches the packet's next hop.
    return true;
}
