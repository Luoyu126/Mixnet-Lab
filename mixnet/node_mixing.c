#include "node_internal.h"

#include <stdlib.h>

static void discard_mixed_packets(struct node_state *state) {
    for (uint16_t i = 0; i < state->mix_count; i++) {
        free(state->mix_buffer[i].packet);
        state->mix_buffer[i].packet = NULL;
    }
    state->mix_count = 0;
}

void release_mixing_buffer(struct node_state *state) {
    discard_mixed_packets(state);
    free(state->mix_buffer);
    state->mix_buffer = NULL;
}

bool enqueue_mixed_packet(void *handle, const struct mixnet_node_config *c,
                           struct node_state *state, uint8_t port,
                           mixnet_packet *packet) {
    // Route preparation is complete; retain both ownership and the next port.
    state->mix_buffer[state->mix_count++] = (struct mixed_packet) {packet, port};
    if (state->mix_count < c->mixing_factor) {
        return true; // Return to the main loop so it can collect more packets.
    }

    // Drain exactly one full batch in arrival order, without rerunning routing.
    for (uint16_t i = 0; i < state->mix_count; i++) {
        struct mixed_packet *entry = &state->mix_buffer[i];
        mixnet_packet *outgoing = entry->packet;
        entry->packet = NULL; // send_routed_packet consumes it even on failure.
        if (!send_routed_packet(handle, entry->port, outgoing)) {
            discard_mixed_packets(state);
            return false;
        }
    }
    state->mix_count = 0;
    return true;
}
