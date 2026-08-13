/*
 * Copyright 2023, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "apf_interpreter.h"
#include "test_buf_allocator.h"

packet_buffer *head = NULL;
packet_buffer *tail = NULL;
uint8_t apf_test_tx_dscp;

/**
 * Test implementation of apf_allocate_buffer()
 *
 * This is a reference apf_allocate_buffer() implementation for testing purpose.
 * It supports being called multiple times for each apf_run().
 * Allocate a new buffer and attach next to the current buffer, then move the current to it.
 * Return the pointer to beginning of the allocated buffer region.
 */
static uint8_t *do_apf_allocate_buffer(__attribute__ ((unused)) struct apf_fw_ctx *ctx, uint32_t size, bool ingress) {
  if (size > BUFFER_SIZE) {
    return NULL;
  }

  packet_buffer *ptr = (packet_buffer *) malloc(sizeof(packet_buffer));
  if (!ptr) {
    fprintf(stderr, "failed to allocate buffer!\n");
    return NULL;
  }

  memset(ptr->data, 0xff, sizeof(ptr->data));
  ptr->next = NULL;
  ptr->len = 0;
  ptr->ingress = ingress;

  if (!head) {
    // the first buffer allocated
    head = ptr;
    tail = head;
  } else {
    // append allocated buffer, and move current to the next
    tail->next = ptr;
    tail = tail->next;
  }

  return ptr->data;
}

uint8_t *apf_allocate_rx_buffer(struct apf_fw_ctx *ctx, uint32_t size) {
  return do_apf_allocate_buffer(ctx, size, /*ingress*/true);
}

uint8_t *apf_allocate_tx_buffer(struct apf_fw_ctx *ctx, uint32_t size) {
  return do_apf_allocate_buffer(ctx, size, /*ingress*/false);
}

uint8_t *apf_allocate_buffer(struct apf_fw_ctx *ctx, uint32_t size) {
  return apf_allocate_tx_buffer(ctx, size);
}

/**
 * Test implementation of apf_transmit_buffer()
 *
 * This is a reference apf_transmit_buffer() implementation for testing purpose.
 * Update the buffer length and dscp value from the transmit packet.
 */
static int do_apf_transmit_buffer(__attribute__((unused)) struct apf_fw_ctx *ctx, uint8_t *ptr,
                           uint32_t len, uint8_t dscp, bool ingress) {
  if (len && len < ETH_HLEN) return -1;
  if (!tail || (ptr != tail->data)) return -1;
  if (ingress != tail->ingress) abort();

  tail->len = len;
  apf_test_tx_dscp = dscp;
  return 0;
}

int apf_transmit_rx_buffer(struct apf_fw_ctx *ctx, uint8_t *ptr, uint32_t len, uint8_t dscp) {
  return do_apf_transmit_buffer(ctx, ptr, len, dscp, /*ingress*/true);
}

int apf_transmit_tx_buffer(struct apf_fw_ctx *ctx, uint8_t *ptr, uint32_t len, uint8_t dscp,
                            __attribute__((unused)) apf_transmit_type type) {
  return do_apf_transmit_buffer(ctx, ptr, len, dscp, /*ingress*/false);
}

int apf_transmit_buffer(struct apf_fw_ctx *ctx, uint8_t *ptr, uint32_t len, uint8_t dscp) {
  return apf_transmit_tx_buffer(ctx, ptr, len, dscp, UNICAST_RETURN);
}

void *apf_allocate_state(__attribute__((unused)) struct apf_fw_ctx *ctx, uint32_t size) {
  return malloc(size);
}

void apf_free_state(__attribute__((unused)) struct apf_fw_ctx *ctx, void *ptr, __attribute__((unused)) uint32_t size) {
  free(ptr);
}

uint32_t apf_get_time_in_ticks(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts)) abort();

  // Convert to 1/16384ths of a second
  uint64_t ticks = (uint64_t)ts.tv_sec * 16384;
  ticks += ((uint64_t)ts.tv_nsec * 16384) / 1000000000ULL;
  return (uint32_t)ticks;
}

void apf_set_timer(__attribute__((unused)) uint32_t relative_ticks, __attribute__((unused)) uint32_t precision_ticks) {
}

void apf_global_lock(void) {
}

void apf_global_unlock(void) {
}
