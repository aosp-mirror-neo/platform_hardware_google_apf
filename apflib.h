/*
 * Copyright 2025, The Android Open Source Project
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

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Returns a zero-terminated array of (at least one) supported versions in increasing order.
const uint32_t* apf_supported_versions();

int apf_run_generic(const uint32_t apf_version,
                    uint32_t * const program,
                    const uint32_t program_len,
                    const uint32_t ram_len,
                    const uint8_t *packet,
                    const uint32_t packet_len,
                    const uint32_t filter_age_16384ths);

struct apf_fw_ctx;
struct apf_state;

struct apf_state *apf_session_create(struct apf_fw_ctx *ctx,
                                     const uint8_t *program,
                                     uint32_t program_len,
                                     uint32_t ram_len);

int apf_session_run_packet(struct apf_state *state,
                           const uint8_t *packet,
                           uint32_t packet_len,
                           uint32_t filter_age_16384ths);

void apf_session_suspend(struct apf_state *state);

void apf_session_resume(struct apf_state *state);

int apf_session_read_data(struct apf_state *state,
                          uint8_t *buf,
                          uint32_t length);

// Simulates the firmware timer firing at 'now_16384ths' (same time base as the
// filter_age_16384ths of apf_session_run_packet()): calls apf_process_timer_event() until it
// returns false, like the firmware does. Returns the number of timer events run.
int apf_session_process_timer_events(uint32_t now_16384ths);

void apf_session_destroy(struct apf_state *state);

#ifdef __cplusplus
}
#endif
