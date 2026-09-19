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
#ifndef MIXNET_NODE_INTERNAL_H_
#define MIXNET_NODE_INTERNAL_H_

#include "config.h"
#include "packet.h"

#include <stdbool.h>
#include <stdint.h>

/* Latest STP information learned from one neighbor port. */
struct neighbor_record {
    mixnet_address neighbor_address;
    mixnet_address advertised_root;
    uint16_t advertised_hops;
    uint64_t last_update_time_ms;
    bool advertisement_valid;
};

/* The best root information currently selected by this node. */
struct best_root {
    mixnet_address root_address;
    uint16_t root_port;
    uint16_t root_hops;
    uint64_t last_hello_time_ms;
};

/* One owned routing result. path[] includes both source and destination.
 * node_count counts addresses, unlike the packet's route_length field.
 * A route to the source itself contains one address and has zero cost. */
struct route_record {
    uint64_t total_cost;
    size_t node_count;
    mixnet_address path[];
};

struct mixed_packet {
    mixnet_packet *packet;
    uint8_t port;
};

/* Owns all state allocated for one invocation of run_node(). */
struct node_state {
    struct neighbor_record *neighbor_records;
    struct best_root best_root;
    uint64_t stp_last_change_time_ms;
    uint64_t stp_quiet_elapsed_ms;
    bool lsa_sent_in_quiet_period;
    uint64_t lsa_last_send_time_ms;
    /* Address-indexed owned copies of received LSA payloads.
     * Capacity covers the largest recorded address; empty slots are NULL. */
    mixnet_packet_lsa **lsa_records;
    size_t lsa_records_capacity;
    /* Indexed by destination address; NULL means no route is stored. */
    struct route_record **routes;
    size_t routes_capacity;
    uint64_t last_ping_rtt_ms;
    bool has_ping_rtt;
    unsigned int random_route_seed;
    struct mixed_packet *mix_buffer;
    uint16_t mix_count;
};

/* Copy an already computed full path; preserve the old entry on failure. */
bool store_route_path(struct node_state *state,
                      mixnet_address destination,
                      uint64_t total_cost,
                      const mixnet_address *path,
                      size_t node_count);

void clear_route_paths(struct node_state *state);

/* Allocate a full path using the student's segment-repetition rule.
 * The base route has at least two nodes and fits max_node_count. */
mixnet_address *create_random_path(const struct route_record *route,
                                   size_t max_node_count,
                                   unsigned int *random_seed,
                                   size_t *node_count);

/* Requires a valid node configuration initialized by the framework.
 * Build full paths using temporary working state, then replace routes only
 * after the entire computation succeeds. See CP2_DESIGN_NOTES.md for the
 * student-selected random pool tie rule and its known zero-cost limitation. */
bool recompute_shortest_paths(const struct mixnet_node_config *c,
                              struct node_state *state);

bool get_monotonic_time_ms(uint64_t *time_ms);

/* Shared CP1 tree-port eligibility for FLOOD and LSA traffic. */
bool stp_port_forwards_flood(const struct mixnet_node_config *c,
                             const struct node_state *state,
                             uint16_t port);

/* Called after the main loop updates the quiet-period clock.
 * Returns false on failure; waiting for a deadline is a successful no-op. */
bool handle_lsa_send_timer(void *handle,
                           const struct mixnet_node_config *c,
                           struct node_state *state,
                           bool stp_changed,
                           uint64_t current_time_ms,
                           uint64_t quiet_interval_ms,
                           uint64_t repeat_interval_ms);

bool handle_lsa_packet(void *handle,
                       const struct mixnet_node_config *c,
                       struct node_state *state,
                       uint8_t port,
                       mixnet_packet *packet);

/* Shared DATA/PING source routing.
 * Consumes the non-NULL packet, including packets dropped for invalid routes. */
bool handle_routed_packet(void *handle,
                        const struct mixnet_node_config *c,
                        struct node_state *state,
                        uint8_t port,
                        mixnet_packet *packet);

/* Direct send consumes the packet; forward transfers ownership to mixing. */
bool send_routed_packet(void *handle, uint8_t port, mixnet_packet *packet);
bool forward_routed_packet(void *handle, const struct mixnet_node_config *c,
                           struct node_state *state, mixnet_packet *packet);

/* Owns the packet until a full batch is sent or the node shuts down.
 * true can mean successfully buffered, rather than already transmitted. */
bool enqueue_mixed_packet(void *handle, const struct mixnet_node_config *c,
                           struct node_state *state, uint8_t port,
                           mixnet_packet *packet);
void release_mixing_buffer(struct node_state *state);

/* Initializes an already validated user PING; does not take ownership. */
bool initialize_ping_request(mixnet_packet *packet);
/* Consumes a complete PING at its destination, delivering and replying as needed. */
bool handle_ping_destination(void *handle, const struct mixnet_node_config *c,
                              struct node_state *state, mixnet_packet *packet);

bool send_initial_stp(void *handle,
                      const struct mixnet_node_config *c,
                      struct node_state *state);

bool handle_stp_packet(void *handle,
                       const struct mixnet_node_config *c,
                       struct node_state *state,
                       uint8_t port,
                       mixnet_packet *packet,
                       bool *state_changed);

bool handle_flood_packet(void *handle,
                         const struct mixnet_node_config *c,
                         struct node_state *state,
                         uint8_t port,
                         mixnet_packet *packet);

enum node_timer_result {
    NODE_TIMER_ERROR = -1,
    NODE_TIMER_IDLE = 0,
    NODE_TIMER_HANDLED = 1,
};

enum node_timer_result handle_expired_timer(void *handle,
                          const struct mixnet_node_config *c,
                          struct node_state *state,
                          bool *state_changed);

bool handle_received_packet(void *handle,
                            const struct mixnet_node_config *c,
                            struct node_state *state,
                            uint8_t port,
                            mixnet_packet *packet,
                            bool *state_changed);

/* Each handler sets *state_changed (required, non-NULL) on every call.
 * It reports changes to non-time STP fields, independently of success/error.
 * The caller owns the quiet-period timing and future LSA scheduling. */

#endif // MIXNET_NODE_INTERNAL_H_
