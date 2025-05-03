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
#ifdef __cplusplus
extern "C" {
#endif

int apf_run_generic(const uint32_t apf_version,
                    uint32_t * const program,
                    const uint32_t program_len,
                    const uint32_t ram_len,
                    const uint8_t *packet,
                    const uint32_t packet_len,
                    const uint32_t filter_age_16384ths);

#ifdef __cplusplus
}
#endif
