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
uint8_t* apf_allocate_buffer(__attribute__ ((unused)) void* ctx, uint32_t size) {
  if (size > BUFFER_SIZE) {
    return NULL;
  }

  packet_buffer* ptr = (packet_buffer *) malloc(sizeof(packet_buffer));
  if (!ptr) {
    fprintf(stderr, "failed to allocate buffer!\n");
    return NULL;
  }

  memset(ptr->data, 0xff, sizeof(ptr->data));
  ptr->next = NULL;
  ptr->len = 0;

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

/**
 * Test implementation of apf_transmit_buffer()
 *
 * This is a reference apf_transmit_buffer() implementation for testing purpose.
 * Update the buffer length and dscp value from the transmit packet.
 */
int apf_transmit_buffer(__attribute__((unused)) void* ctx, uint8_t* ptr,
                        uint32_t len, uint8_t dscp) {
  if (len && len < ETH_HLEN) return -1;
  if (!tail || (ptr != tail->data)) return -1;

  tail->len = len;
  apf_test_tx_dscp = dscp;
  return 0;
}
