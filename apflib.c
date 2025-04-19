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
#include <v4/apf_interpreter.h>
// TODO: avoid copy/paste for different version interpreters
#define apf_run apfv6__apf_run
#define apf_version apfv6__apf_version
#include <v6/apf_interpreter.h>
#undef apf_run
#undef apf_version

#define apf_run apfv61__apf_run
#define apf_version apfv61__apf_version
#include <v6.1/apf_interpreter.h>
#undef apf_run
#undef apf_version

#include <next/apf_interpreter.h>

#define APF_VERSION_V2 2
#define APF_VERSION_V4 4
#define APF_VERSION_V6 (int)apfv6__apf_version()
#define APF_VERSION_V61 (int)apfv61__apf_version()

int apf_run_generic(int apf_version, uint32_t* program,
                    uint32_t program_len, uint32_t ram_len,
                    const uint8_t* packet, uint32_t packet_len,
                    uint32_t filter_age) {
    if (apf_version < APF_VERSION_V2) {
        return -1;
    }

    // TODO: handle APFv2 version interpreter
    if (apf_version <= APF_VERSION_V4) {
        return accept_packet((uint8_t*)program, program_len, ram_len, packet, packet_len,
                             filter_age >> 14);
    }

    if (apf_version < APF_VERSION_V6) {
        return accept_packet((uint8_t*)program, program_len, ram_len, packet, packet_len,
                             filter_age >> 14);
    }

    if (apf_version < APF_VERSION_V61) {
        return apfv6__apf_run(nullptr, program, program_len, ram_len, packet, packet_len,
                          filter_age);
    }

    if (apf_version == APF_VERSION_V61) {
        return apfv61__apf_run(nullptr, program, program_len, ram_len, packet, packet_len,
                          filter_age);
    }

    return apf_run(nullptr, program, program_len, ram_len, packet, packet_len,
                    filter_age);
}
