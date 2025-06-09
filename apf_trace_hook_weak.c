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

#include <inttypes.h>

void __attribute__((weak)) apf_trace_hook(uint32_t pc, const uint32_t* regs,
                                          const uint8_t* program, uint32_t program_len,
                                          const uint8_t* packet, uint32_t packet_len,
                                          const uint32_t* memory, uint32_t memory_len);

void apf_trace_hook(uint32_t pc __attribute__((unused)),
                    const uint32_t* regs __attribute__((unused)),
                    const uint8_t* program __attribute__((unused)),
                    uint32_t program_len __attribute__((unused)),
                    const uint8_t* packet __attribute__((unused)),
                    uint32_t packet_len __attribute__((unused)),
                    const uint32_t* memory __attribute__((unused)),
                    uint32_t memory_len __attribute__((unused))) {}
