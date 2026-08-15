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

#define accept_packet apfv2__accept_packet
#include <v2/apf_interpreter.h>
#undef accept_packet
#undef APF_VERSION  // 2

#define accept_packet apfv4__accept_packet
#include <v4/apf_interpreter.h>
#undef accept_packet
#undef APF_VERSION  // 4

#define apf_run apfv6__apf_run
#define apf_version apfv6__apf_version
#include <v6/apf_interpreter.h>
#undef apf_run
#undef apf_version  // returns 6000

#define apf_run apfv61__apf_run
#define apf_version apfv61__apf_version
#include <v6.1/apf_interpreter.h>
#undef apf_run
#undef apf_version  // returns 6100

#define apf_get_info apfnext__apf_get_info
#define apf_set_id apfnext__apf_set_id
#define apf_enable apfnext__apf_enable
#define apf_get_ram_size apfnext__apf_get_ram_size
#define apf_read apfnext__apf_read
#define apf_write apfnext__apf_write
#define apf_disable apfnext__apf_disable
#define apf_suspend apfnext__apf_suspend
#define apf_resume apfnext__apf_resume
#define apf_ticks_until_next_timer_event apfnext__apf_ticks_until_next_timer_event
#define apf_process_timer_event apfnext__apf_process_timer_event
#define apf_run_packet apfnext__apf_run_packet
#include <next/apf_interpreter.h>
#undef apf_get_info
#undef apf_set_id
#undef apf_enable
#undef apf_get_ram_size
#undef apf_read
#undef apf_write
#undef apf_disable
#undef apf_suspend
#undef apf_resume
#undef apf_ticks_until_next_timer_event
#undef apf_process_timer_event
#undef apf_run_packet

#include "apflib.h"

void apf_test_set_time_in_ticks(uint32_t ticks);
void apf_test_clear_time_in_ticks(void);

#define EXCEPTION 2

static int apfnext_run(struct apf_fw_ctx *ctx, uint8_t *program,
                       uint32_t program_len, uint32_t ram_len,
                       const uint8_t *packet, uint32_t packet_len,
                       uint32_t filter_age_16384ths) {
    if (program_len > ram_len) return EXCEPTION;
    const uint32_t data_len = ram_len - program_len;
    uint8_t * const data = program + program_len;
    int result = EXCEPTION;

    struct apf_state *state = apfnext__apf_enable(ctx, ram_len);
    if (!state) return EXCEPTION;

    const uint32_t actual_ram_len = apfnext__apf_get_ram_size(state);
    if (actual_ram_len < ram_len) goto cleanup;

    const uint32_t data_offset = actual_ram_len - data_len;

    apf_test_set_time_in_ticks(0);
    if (apfnext__apf_write(state, -1, program, program_len)) goto cleanup;
    if (data_len && apfnext__apf_write(state, (int32_t)data_offset, data, data_len)) goto cleanup;

    apf_test_set_time_in_ticks(filter_age_16384ths);
    result = apfnext__apf_run_packet(state, packet, packet_len);
    if (data_len) apfnext__apf_read(state, data_offset, data, data_len);

cleanup:
    apf_test_clear_time_in_ticks();
    apfnext__apf_disable(state);
    return result;
}

const uint32_t* apf_supported_versions() {
    const int NUM_VERSIONS = 6;
    // Array includes an extra element for zero termination.
    static uint32_t versions[NUM_VERSIONS + 1];
    versions[0] = 2;
    versions[1] = 3;
    versions[2] = 4;
    versions[3] = apfv6__apf_version();
    versions[4] = apfv61__apf_version();

    struct apf_info info = {};
    apfnext__apf_get_info(&info);
    versions[5] = info.apf_version;

    versions[6] = 0; // zero terminator
    return versions;
}

int apf_run_generic(const uint32_t apf_version,
                    uint32_t* const program,
                    const uint32_t program_len,
                    const uint32_t ram_len,
                    const uint8_t* packet,
                    const uint32_t packet_len,
                    const uint32_t filter_age_16384ths) {
    uint8_t * const program8 = (uint8_t*)program;
    const uint32_t filter_age = filter_age_16384ths >> 14;
    void * const ctx = nullptr;

    if (apf_version == 2)
        return apfv2__accept_packet(program8, program_len, packet, packet_len, filter_age);

    // Note: APFv3 is just APFv4 with somewhat broken memory/counter read API.
    if (apf_version == 3 || apf_version == 4)
        return apfv4__accept_packet(program8, program_len, ram_len, packet, packet_len, filter_age);

    if (apf_version == apfv6__apf_version())  // 6000
        return apfv6__apf_run(ctx, program, program_len, ram_len, packet, packet_len, filter_age_16384ths);

    if (apf_version == apfv61__apf_version())  // 6100
        return apfv61__apf_run(ctx, program, program_len, ram_len, packet, packet_len, filter_age_16384ths);

    if (apf_version >= 7000) // hardcoded (for now) to allow evolving apfnext__apf_version()
        return apfnext_run(ctx, program8, program_len, ram_len, packet, packet_len,
                           filter_age_16384ths);

    return -1;
}
