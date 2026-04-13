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

#ifndef TEST_BUF_ALLOCATOR
#define TEST_BUF_ALLOCATOR

#include <stdint.h>
#include <linux/if_ether.h>

#define BUFFER_SIZE 1514

typedef struct packet_buffer {
    uint8_t data[BUFFER_SIZE];
    uint32_t len;
    bool ingress;
    struct packet_buffer *next;
} packet_buffer;

extern packet_buffer *head;
extern packet_buffer *tail;
extern uint8_t apf_test_tx_dscp;

// due to -Wmissing-prototype we need to declare these functions which
// older (than next) interpreters need at link time
//
// declarations of functions used/needed by 'next' interpreter will
// come from our inclusion of next/apf_interpreter.h
struct apf_fw_ctx;
uint8_t *apf_allocate_buffer(struct apf_fw_ctx *ctx, uint32_t size);
int apf_transmit_buffer(struct apf_fw_ctx *ctx, uint8_t *ptr, uint32_t len, uint8_t dscp);

#endif  // TEST_BUF_ALLOCATOR
