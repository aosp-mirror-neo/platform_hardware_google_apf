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

#define apf_run apfnext__apf_run
#define apf_version apfnext__apf_version
#include <next/apf_interpreter.h>
#undef apf_run
#undef apf_version

#include "apflib.h"

const uint32_t* apf_supported_versions() {
    const int NUM_VERSIONS = 6;
    // Array includes an extra element for zero termination.
    static uint32_t versions[NUM_VERSIONS + 1];
    versions[0] = 2;
    versions[1] = 3;
    versions[2] = 4;
    versions[3] = apfv6__apf_version();
    versions[4] = apfv61__apf_version();
    versions[5] = apfnext__apf_version();
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
        return apfnext__apf_run(ctx, program, program_len, ram_len, packet, packet_len, filter_age_16384ths);

    return -1;
}
