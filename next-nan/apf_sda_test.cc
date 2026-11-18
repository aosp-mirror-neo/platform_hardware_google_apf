/*
 * Copyright 2026, The Android Open Source Project
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

#include <stdint.h>
#include <gtest/gtest.h>

#include "apf_interpreter.h"
#include "../next/apf_defs.h"
#include "apf_sda.h"

namespace apf {

namespace crc_mode_bitwise {
#undef APF_SDA_H_
#undef APF_CRC32_IMPL
#define APF_CRC32_IMPL APF_CRC32_BITWISE
#include "apf_sda.h"
}  // namespace crc_mode_bitwise

namespace crc_mode_custom {
static uint32_t g_custom_crc32_call_count = 0;
#undef APF_SDA_H_
#undef APF_CRC32_IMPL
#define APF_CRC32_IMPL APF_CRC32_EXTERNAL
#include "apf_sda.h"
extern "C" uint32_t apf_ieee80211_crc32(const uint8_t* buf, uint32_t len) {
    g_custom_crc32_call_count++;
    return crc_mode_bitwise::apf_ieee80211_crc32(buf, len);
}
}  // namespace crc_mode_custom
#undef APF_CRC32_IMPL
#define APF_CRC32_IMPL APF_CRC32_TABLE

// A misspelled APF_CRC32_IMPL name evaluates as 0 in #if. The valid values must be distinct
// and non-zero so that such a name hits the #error in apf_sda.h.
static_assert(APF_CRC32_TABLE != 0 && APF_CRC32_BITWISE != 0 && APF_CRC32_EXTERNAL != 0,
              "APF_CRC32_* values must be non-zero");
static_assert(APF_CRC32_TABLE != APF_CRC32_BITWISE && APF_CRC32_TABLE != APF_CRC32_EXTERNAL &&
                      APF_CRC32_BITWISE != APF_CRC32_EXTERNAL,
              "APF_CRC32_* values must be distinct");

static const uint8_t kTargetServiceId[6] = {0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf};
static const uint8_t kZeroServiceId[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t kLocalNmi[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t kOtherNmi[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01};

// Reference IEEE 802.11 FCS CRC-32 lookup table and implementation from
// external/wpa_supplicant_8/src/utils/crc32.c to verify that our table-less
// bitwise apf_ieee80211_crc32() produces identical outputs across all inputs.
static const uint32_t kWpaSupplicantCrc32Table[256] = {
    0x00000000u, 0x77073096u, 0xee0e612cu, 0x990951bau, 0x076dc419u,
    0x706af48fu, 0xe963a535u, 0x9e6495a3u, 0x0edb8832u, 0x79dcb8a4u,
    0xe0d5e91eu, 0x97d2d988u, 0x09b64c2bu, 0x7eb17cbdu, 0xe7b82d07u,
    0x90bf1d91u, 0x1db71064u, 0x6ab020f2u, 0xf3b97148u, 0x84be41deu,
    0x1adad47du, 0x6ddde4ebu, 0xf4d4b551u, 0x83d385c7u, 0x136c9856u,
    0x646ba8c0u, 0xfd62f97au, 0x8a65c9ecu, 0x14015c4fu, 0x63066cd9u,
    0xfa0f3d63u, 0x8d080df5u, 0x3b6e20c8u, 0x4c69105eu, 0xd56041e4u,
    0xa2677172u, 0x3c03e4d1u, 0x4b04d447u, 0xd20d85fdu, 0xa50ab56bu,
    0x35b5a8fau, 0x42b2986cu, 0xdbbbc9d6u, 0xacbcf940u, 0x32d86ce3u,
    0x45df5c75u, 0xdcd60dcfu, 0xabd13d59u, 0x26d930acu, 0x51de003au,
    0xc8d75180u, 0xbfd06116u, 0x21b4f4b5u, 0x56b3c423u, 0xcfba9599u,
    0xb8bda50fu, 0x2802b89eu, 0x5f058808u, 0xc60cd9b2u, 0xb10be924u,
    0x2f6f7c87u, 0x58684c11u, 0xc1611dabu, 0xb6662d3du, 0x76dc4190u,
    0x01db7106u, 0x98d220bcu, 0xefd5102au, 0x71b18589u, 0x06b6b51fu,
    0x9fbfe4a5u, 0xe8b8d433u, 0x7807c9a2u, 0x0f00f934u, 0x9609a88eu,
    0xe10e9818u, 0x7f6a0dbbu, 0x086d3d2du, 0x91646c97u, 0xe6635c01u,
    0x6b6b51f4u, 0x1c6c6162u, 0x856530d8u, 0xf262004eu, 0x6c0695edu,
    0x1b01a57bu, 0x8208f4c1u, 0xf50fc457u, 0x65b0d9c6u, 0x12b7e950u,
    0x8bbeb8eau, 0xfcb9887cu, 0x62dd1ddfu, 0x15da2d49u, 0x8cd37cf3u,
    0xfbd44c65u, 0x4db26158u, 0x3ab551ceu, 0xa3bc0074u, 0xd4bb30e2u,
    0x4adfa541u, 0x3dd895d7u, 0xa4d1c46du, 0xd3d6f4fbu, 0x4369e96au,
    0x346ed9fcu, 0xad678846u, 0xda60b8d0u, 0x44042d73u, 0x33031de5u,
    0xaa0a4c5fu, 0xdd0d7cc9u, 0x5005713cu, 0x270241aau, 0xbe0b1010u,
    0xc90c2086u, 0x5768b525u, 0x206f85b3u, 0xb966d409u, 0xce61e49fu,
    0x5edef90eu, 0x29d9c998u, 0xb0d09822u, 0xc7d7a8b4u, 0x59b33d17u,
    0x2eb40d81u, 0xb7bd5c3bu, 0xc0ba6cadu, 0xedb88320u, 0x9abfb3b6u,
    0x03b6e20cu, 0x74b1d29au, 0xead54739u, 0x9dd277afu, 0x04db2615u,
    0x73dc1683u, 0xe3630b12u, 0x94643b84u, 0x0d6d6a3eu, 0x7a6a5aa8u,
    0xe40ecf0bu, 0x9309ff9du, 0x0a00ae27u, 0x7d079eb1u, 0xf00f9344u,
    0x8708a3d2u, 0x1e01f268u, 0x6906c2feu, 0xf762575du, 0x806567cbu,
    0x196c3671u, 0x6e6b06e7u, 0xfed41b76u, 0x89d32be0u, 0x10da7a5au,
    0x67dd4accu, 0xf9b9df6fu, 0x8ebeeff9u, 0x17b7be43u, 0x60b08ed5u,
    0xd6d6a3e8u, 0xa1d1937eu, 0x38d8c2c4u, 0x4fdff252u, 0xd1bb67f1u,
    0xa6bc5767u, 0x3fb506ddu, 0x48b2364bu, 0xd80d2bdau, 0xaf0a1b4cu,
    0x36034af6u, 0x41047a60u, 0xdf60efc3u, 0xa867df55u, 0x316e8eefu,
    0x4669be79u, 0xcb61b38cu, 0xbc66831au, 0x256fd2a0u, 0x5268e236u,
    0xcc0c7795u, 0xbb0b4703u, 0x220216b9u, 0x5505262fu, 0xc5ba3bbeu,
    0xb2bd0b28u, 0x2bb45a92u, 0x5cb36a04u, 0xc2d7ffa7u, 0xb5d0cf31u,
    0x2cd99e8bu, 0x5bdeae1du, 0x9b64c2b0u, 0xec63f226u, 0x756aa39cu,
    0x026d930au, 0x9c0906a9u, 0xeb0e363fu, 0x72076785u, 0x05005713u,
    0x95bf4a82u, 0xe2b87a14u, 0x7bb12baeu, 0x0cb61b38u, 0x92d28e9bu,
    0xe5d5be0du, 0x7cdcefb7u, 0x0bdbdf21u, 0x86d3d2d4u, 0xf1d4e242u,
    0x68ddb3f8u, 0x1fda836eu, 0x81be16cdu, 0xf6b9265bu, 0x6fb077e1u,
    0x18b74777u, 0x88085ae6u, 0xff0f6a70u, 0x66063bcau, 0x11010b5cu,
    0x8f659effu, 0xf862ae69u, 0x616bffd3u, 0x166ccf45u, 0xa00ae278u,
    0xd70dd2eeu, 0x4e048354u, 0x3903b3c2u, 0xa7672661u, 0xd06016f7u,
    0x4969474du, 0x3e6e77dbu, 0xaed16a4au, 0xd9d65adcu, 0x40df0b66u,
    0x37d83bf0u, 0xa9bcae53u, 0xdebb9ec5u, 0x47b2cf7fu, 0x30b5ffe9u,
    0xbdbdf21cu, 0xcabac28au, 0x53b39330u, 0x24b4a3a6u, 0xbad03605u,
    0xcdd70693u, 0x54de5729u, 0x23d967bfu, 0xb3667a2eu, 0xc4614ab8u,
    0x5d681b02u, 0x2a6f2b94u, 0xb40bbe37u, 0xc30c8ea1u, 0x5a05df1bu,
    0x2d02ef8du
};

static uint32_t wpa_supplicant_ieee80211_crc32(const uint8_t* frame, uint32_t frame_len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < frame_len; i++) {
        crc = kWpaSupplicantCrc32Table[(crc ^ frame[i]) & 0xffu] ^ (crc >> 8u);
    }
    return ~crc;
}

TEST(ApfSdaTest, Ieee80211Crc32MatchesWpaSupplicantLookupTable) {
    // 1. Empty input (verify the table, bitwise, and external implementations)
    const uint8_t empty[] = {0x00};
    EXPECT_EQ(apf_ieee80211_crc32(empty, 0), 0x00000000u);
    EXPECT_EQ(crc_mode_bitwise::apf_ieee80211_crc32(empty, 0), 0x00000000u);
    EXPECT_EQ(crc_mode_custom::apf_ieee80211_crc32(empty, 0), 0x00000000u);
    EXPECT_EQ(apf_ieee80211_crc32(empty, 0), wpa_supplicant_ieee80211_crc32(empty, 0));

    // 2. Standard IEEE 802.11 / ISO-HDLC check vector ("123456789" -> 0xCBF43926)
    const uint8_t check_vec[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    EXPECT_EQ(apf_ieee80211_crc32(check_vec, sizeof(check_vec)), 0xCBF43926u);
    EXPECT_EQ(crc_mode_bitwise::apf_ieee80211_crc32(check_vec, sizeof(check_vec)), 0xCBF43926u);
    EXPECT_EQ(crc_mode_custom::apf_ieee80211_crc32(check_vec, sizeof(check_vec)), 0xCBF43926u);
    EXPECT_EQ(apf_ieee80211_crc32(check_vec, sizeof(check_vec)),
              wpa_supplicant_ieee80211_crc32(check_vec, sizeof(check_vec)));

    // 3. All 256 single-byte values must match wpa_supplicant's 256-entry table across all modes
    for (uint32_t v = 0; v < 256; v++) {
        const uint8_t b = static_cast<uint8_t>(v);
        EXPECT_EQ(apf_ieee80211_crc32(&b, 1), wpa_supplicant_ieee80211_crc32(&b, 1));
        EXPECT_EQ(crc_mode_bitwise::apf_ieee80211_crc32(&b, 1),
                  wpa_supplicant_ieee80211_crc32(&b, 1));
    }

    // 4. All 16 NAN Bloom filter hash inputs a_j_x = [j || NMI] (j = 0..15, bf_idx = 0..3)
    const uint8_t test_nmis[][6] = {
        {0x1a, 0xca, 0x57, 0x00, 0x00, 0x01},
        {0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
        {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
    };
    for (const auto& nmi : test_nmis) {
        for (uint8_t j = 0; j < 16; j++) {
            const uint8_t a_j_x[7] = {j, nmi[0], nmi[1], nmi[2], nmi[3], nmi[4], nmi[5]};
            const uint32_t apf_crc = apf_ieee80211_crc32(a_j_x, sizeof(a_j_x));
            const uint32_t bitwise_crc =
                crc_mode_bitwise::apf_ieee80211_crc32(a_j_x, sizeof(a_j_x));
            const uint32_t wpa_crc = wpa_supplicant_ieee80211_crc32(a_j_x, sizeof(a_j_x));
            EXPECT_EQ(apf_crc, wpa_crc);
            EXPECT_EQ(bitwise_crc, wpa_crc);
            EXPECT_EQ((~apf_crc) & 0xFFFFu, (~wpa_crc) & 0xFFFFu);
        }
    }

    // 5. Verify Bloom filter matching with all 3 APF_CRC32_IMPL values:
    //    APF_CRC32_TABLE, APF_CRC32_BITWISE, and APF_CRC32_EXTERNAL (custom firmware hook).
    uint8_t bf[8] = {0};
    for (uint8_t j = 0; j < 4; j++) {
        const uint8_t a_j_x[7] = {
            j, kLocalNmi[0], kLocalNmi[1], kLocalNmi[2], kLocalNmi[3], kLocalNmi[4], kLocalNmi[5]
        };
        const uint32_t crc = (~wpa_supplicant_ieee80211_crc32(a_j_x, sizeof(a_j_x))) & 0xFFFFu;
        const uint32_t bit = crc % (sizeof(bf) * 8u);
        bf[bit / 8u] |= static_cast<uint8_t>(1u << (bit % 8u));
    }
    EXPECT_TRUE(apf_nan_check_bloom_filter(kLocalNmi, bf, sizeof(bf), 0));
    EXPECT_TRUE(crc_mode_bitwise::apf_nan_check_bloom_filter(kLocalNmi, bf, sizeof(bf), 0));
    crc_mode_custom::g_custom_crc32_call_count = 0;
    EXPECT_TRUE(crc_mode_custom::apf_nan_check_bloom_filter(kLocalNmi, bf, sizeof(bf), 0));
    EXPECT_EQ(crc_mode_custom::g_custom_crc32_call_count, 4u);

    EXPECT_FALSE(apf_nan_check_bloom_filter(kOtherNmi, bf, sizeof(bf), 0));
    EXPECT_FALSE(crc_mode_bitwise::apf_nan_check_bloom_filter(kOtherNmi, bf, sizeof(bf), 0));
    EXPECT_FALSE(crc_mode_custom::apf_nan_check_bloom_filter(kOtherNmi, bf, sizeof(bf), 0));
}

TEST(ApfSdaTest, MatchBasicPublishSubscribeAndFollowUpRoles) {
    // 9-byte minimal Publish SDA (msg_type = 0)
    const uint8_t publish_sda[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, // Service ID
        0x01,                               // Instance ID
        0x00,                               // Requestor Instance ID
        0x00                                // Service Control: Publish (0)
    };
    // Incoming Publish matches local Subscriber (config = 0x01), rejects local Publisher (0x00, 0x04)
    EXPECT_EQ(apf_internal_match_nan_sda(publish_sda, sizeof(publish_sda), 0, sizeof(publish_sda),
                                         kTargetServiceId, 0x01 /* Subscriber */, 0, nullptr),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(publish_sda, sizeof(publish_sda), 0, sizeof(publish_sda),
                                         kTargetServiceId, 0x00 /* Unsolicited-only Publisher */,
                                         0, nullptr),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(publish_sda, sizeof(publish_sda), 0, sizeof(publish_sda),
                                         kTargetServiceId, 0x04 /* Solicited Publisher */,
                                         0, nullptr),
              nan_sda_ignore);

    // 9-byte minimal Subscribe SDA (msg_type = 1)
    const uint8_t subscribe_sda[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, // Service ID
        0x01,                               // Instance ID
        0x00,                               // Requestor Instance ID
        0x01                                // Service Control: Subscribe (1)
    };
    // Incoming Subscribe matches Solicited Publisher (config = 0x04),
    // rejects Unsolicited-only Publisher (0x00) and Subscriber (0x01)
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_sda, sizeof(subscribe_sda), 0,
                                         sizeof(subscribe_sda), kTargetServiceId,
                                         0x04 /* Solicited Publisher */, 0, nullptr),
              nan_sda_subscribe);
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_sda, sizeof(subscribe_sda), 0,
                                         sizeof(subscribe_sda), kTargetServiceId,
                                         0x00 /* Unsolicited-only Publisher */, 0, nullptr),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_sda, sizeof(subscribe_sda), 0,
                                         sizeof(subscribe_sda), kTargetServiceId,
                                         0x01 /* Subscriber */, 0, nullptr),
              nan_sda_ignore);

    // 9-byte minimal Follow-up SDA (msg_type = 2)
    const uint8_t followup_sda[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, // Service ID
        0x01,                               // Instance ID
        0x02,                               // Requestor Instance ID
        0x02                                // Service Control: Follow-up (2)
    };
    // Follow-up matches both Publisher (0x00, 0x04) and Subscriber (0x01)
    EXPECT_EQ(apf_internal_match_nan_sda(followup_sda, sizeof(followup_sda), 0,
                                         sizeof(followup_sda), kTargetServiceId,
                                         0x00 /* Unsolicited-only Publisher */, 0, nullptr),
              nan_sda_follow_up);
    EXPECT_EQ(apf_internal_match_nan_sda(followup_sda, sizeof(followup_sda), 0,
                                         sizeof(followup_sda), kTargetServiceId,
                                         0x04 /* Solicited Publisher */, 0, nullptr),
              nan_sda_follow_up);
    EXPECT_EQ(apf_internal_match_nan_sda(followup_sda, sizeof(followup_sda), 0,
                                         sizeof(followup_sda), kTargetServiceId,
                                         0x01 /* Subscriber */, 0, nullptr),
              nan_sda_follow_up);

    // Reserved Service Control Type (msg_type = 3) is rejected as nan_sda_ignore
    const uint8_t reserved_msg_sda[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x03 /* Reserved type 3 */
    };
    EXPECT_EQ(apf_internal_match_nan_sda(reserved_msg_sda, sizeof(reserved_msg_sda), 0,
                                         sizeof(reserved_msg_sda), kTargetServiceId,
                                         0x01, 0, nullptr),
              nan_sda_ignore);

    // Reserved local_role values (2 and 3) and reserved config bits (bits 4-7) are rejected as nan_sda_error_program
    EXPECT_EQ(apf_internal_match_nan_sda(publish_sda, sizeof(publish_sda), 0, sizeof(publish_sda),
                                         kTargetServiceId, 0x02 /* Reserved role 2 */, 0, nullptr),
              nan_sda_error_program);
    EXPECT_EQ(apf_internal_match_nan_sda(publish_sda, sizeof(publish_sda), 0, sizeof(publish_sda),
                                         kTargetServiceId, 0x03 /* Reserved role 3 */, 0, nullptr),
              nan_sda_error_program);
    EXPECT_EQ(apf_internal_match_nan_sda(publish_sda, sizeof(publish_sda), 0, sizeof(publish_sda),
                                         kTargetServiceId, 0x11 /* Reserved bit 4 */, 0, nullptr),
              nan_sda_error_program);
    EXPECT_EQ(apf_internal_match_nan_sda(publish_sda, sizeof(publish_sda), 0, sizeof(publish_sda),
                                         kTargetServiceId, 0x81 /* Reserved bit 7 */, 0, nullptr),
              nan_sda_error_program);

    // Null pointer guards (including local_nmi == nullptr when srf_enable is set, even if the
    // incoming SDA does not carry an SRF attribute)
    EXPECT_EQ(apf_internal_match_nan_sda(nullptr, sizeof(publish_sda), 0, sizeof(publish_sda),
                                         kTargetServiceId, 0x01, 0, nullptr),
              nan_sda_truncated);
    EXPECT_EQ(apf_internal_match_nan_sda(publish_sda, sizeof(publish_sda), 0, sizeof(publish_sda),
                                         nullptr, 0x01, 0, nullptr),
              nan_sda_error_program);
    EXPECT_EQ(apf_internal_match_nan_sda(publish_sda, sizeof(publish_sda), 0, sizeof(publish_sda),
                                         kTargetServiceId, 0x09 /* Subscriber + SRF enable */, 0,
                                         nullptr),
              nan_sda_error_program);
}

TEST(ApfSdaTest, ServiceIdMatchingAndRandomizationHandling) {
    // Mismatch at each of the 6 Service ID byte positions (when bit 7 is 0)
    for (uint32_t pos = 0; pos < 6; pos++) {
        uint8_t sda[] = {
            0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
            0x01, 0x00, 0x00
        };
        sda[pos] ^= 0xff;
        EXPECT_EQ(apf_internal_match_nan_sda(sda, sizeof(sda), 0, sizeof(sda),
                                             kTargetServiceId, 0x01, 0, nullptr),
                  nan_sda_ignore);
    }

    // Without bit 7 (0x80), a zeroed wire Service ID only matches kZeroServiceId, not kTargetServiceId
    const uint8_t non_randomized_zero_sda[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00 /* Publish without randomization */
    };
    EXPECT_EQ(apf_internal_match_nan_sda(non_randomized_zero_sda, sizeof(non_randomized_zero_sda),
                                         0, sizeof(non_randomized_zero_sda), kTargetServiceId,
                                         0x01, 0, nullptr),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(non_randomized_zero_sda, sizeof(non_randomized_zero_sda),
                                         0, sizeof(non_randomized_zero_sda), kZeroServiceId,
                                         0x01, 0, nullptr),
              nan_sda_publish);

    // Service ID Randomization (srv_ctrl & 0x80, wpa_supplicant NAN_SRV_CTRL_SERVICE_ID_RANDOMIZATION):
    // wpa_supplicant sets the 6-byte wire Service ID in the SDA to all zeros and
    // resolves the real Service ID on the host via IRSA/RSIA + SipHash-2-4.
    // When bit 7 is set, apf_internal_match_nan_sda() skips only the 6-byte
    // Service ID comparison while still enforcing role, requestor instance ID,
    // optional field bounds, and SRF checks.
    const uint8_t randomized_zero_sda[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zeroed Service ID on wire
        0x01,                               // Instance ID
        0x2a,                               // Requestor Instance ID: 42
        0x80                                // Publish (0) | NAN_SRV_CTRL_SERVICE_ID_RANDOMIZATION (0x80)
    };
    // Passes to host (nan_sda_publish) when role and requestor instance ID match
    EXPECT_EQ(apf_internal_match_nan_sda(randomized_zero_sda, sizeof(randomized_zero_sda), 0,
                                         sizeof(randomized_zero_sda), kTargetServiceId,
                                         0x01 /* Subscriber */, 42, nullptr),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(randomized_zero_sda, sizeof(randomized_zero_sda), 0,
                                         sizeof(randomized_zero_sda), kTargetServiceId,
                                         0x01 /* Subscriber */, 0 /* wildcard */, nullptr),
              nan_sda_publish);
    // Still rejects on role conflict (Publish received by Publisher) or mismatched req_instance_id
    EXPECT_EQ(apf_internal_match_nan_sda(randomized_zero_sda, sizeof(randomized_zero_sda), 0,
                                         sizeof(randomized_zero_sda), kTargetServiceId,
                                         0x00 /* Publisher */, 0, nullptr),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(randomized_zero_sda, sizeof(randomized_zero_sda), 0,
                                         sizeof(randomized_zero_sda), kTargetServiceId,
                                         0x01 /* Subscriber */, 99 /* wrong inst_id */, nullptr),
              nan_sda_ignore);

    // Randomized Subscribe with an excluding SRF still enforces SRF filtering
    const uint8_t randomized_srf_exclude_sda[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00,
        0x89,                               // Subscribe (1) | SRF (0x08) | Randomization (0x80)
        0x07, 0x00,                         // SRF len=7, MAC list Exclude
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55  // kLocalNmi
    };
    EXPECT_EQ(apf_internal_match_nan_sda(randomized_srf_exclude_sda,
                                         sizeof(randomized_srf_exclude_sda), 0,
                                         sizeof(randomized_srf_exclude_sda), kTargetServiceId,
                                         0x0c /* Solicited Publisher + SRF enable */, 0, kLocalNmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(randomized_srf_exclude_sda,
                                         sizeof(randomized_srf_exclude_sda), 0,
                                         sizeof(randomized_srf_exclude_sda), kTargetServiceId,
                                         0x0c /* Solicited Publisher + SRF enable */, 0, kOtherNmi),
              nan_sda_subscribe);
}

TEST(ApfSdaTest, RequestorInstanceIdMatching) {
    // Solicited Publish (msg_type = 0, req_instance_id = 42)
    const uint8_t solicited_publish_sda[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
        0x01, // Instance ID: 1
        0x2a, // Requestor Instance ID: 42
        0x00  // Service Control: Publish (0)
    };

    // Subscriber with matching local_inst_id (42) -> match
    EXPECT_EQ(apf_internal_match_nan_sda(solicited_publish_sda, sizeof(solicited_publish_sda), 0,
                                         sizeof(solicited_publish_sda), kTargetServiceId,
                                         0x01 /* Subscriber */, 42, nullptr),
              nan_sda_publish);

    // Subscriber with different local_inst_id (10) -> nan_sda_ignore
    EXPECT_EQ(apf_internal_match_nan_sda(solicited_publish_sda, sizeof(solicited_publish_sda), 0,
                                         sizeof(solicited_publish_sda), kTargetServiceId,
                                         0x01 /* Subscriber */, 10, nullptr),
              nan_sda_ignore);

    // Subscriber with wildcard local_inst_id (0) -> match
    EXPECT_EQ(apf_internal_match_nan_sda(solicited_publish_sda, sizeof(solicited_publish_sda), 0,
                                         sizeof(solicited_publish_sda), kTargetServiceId,
                                         0x01 /* Subscriber */, 0, nullptr),
              nan_sda_publish);

    // Unsolicited Publish (req_instance_id = 0) matches Subscriber with any local_inst_id
    const uint8_t unsolicited_publish_sda[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
        0x01, 0x00 /* req_instance_id = 0 */, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(unsolicited_publish_sda, sizeof(unsolicited_publish_sda),
                                         0, sizeof(unsolicited_publish_sda), kTargetServiceId,
                                         0x01 /* Subscriber */, 10, nullptr),
              nan_sda_publish);

    // Subscribe (msg_type = 1) and Follow-up (msg_type = 2) with non-zero req_instance_id
    // are not rejected by the Publish-only req_instance_id check (per nan_de_rx_sda)
    const uint8_t subscribe_nonzero_req_id_sda[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
        0x01, 0x2a /* req_instance_id = 42 */, 0x01 /* Subscribe */
    };
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_nonzero_req_id_sda,
                                         sizeof(subscribe_nonzero_req_id_sda), 0,
                                         sizeof(subscribe_nonzero_req_id_sda), kTargetServiceId,
                                         0x04 /* Solicited Publisher */, 10, nullptr),
              nan_sda_subscribe);

    const uint8_t followup_sda[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
        0x01, 0x2a /* req_instance_id = 42 */, 0x02 /* Follow-up */
    };
    EXPECT_EQ(apf_internal_match_nan_sda(followup_sda, sizeof(followup_sda), 0,
                                         sizeof(followup_sda), kTargetServiceId,
                                         0x01 /* Subscriber */, 10, nullptr),
              nan_sda_follow_up);
}

TEST(ApfSdaTest, SrfMacAddressListIncludeAndExclude) {
    // 1. Exclude MAC List with 2 MACs (one matches kLocalNmi)
    // srf_ctrl = 0x00: bit 0 = 0 (MAC list), bit 1 = 0 (Exclude mode)
    const uint8_t sda_srf_exclude[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, // Service ID
        0x01, 0x00, 0x08,                   // Publish | NAN_SRV_CTRL_RESP_FILTER (0x08)
        13,                                 // srf_len: 1 (ctrl) + 12 (2 MACs)
        0x00,                               // srf_ctrl: MAC list, Exclude mode
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // MAC 1
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55  // MAC 2 (kLocalNmi)
    };
    // kLocalNmi is in Exclude list -> dropped (nan_sda_ignore) when SRF is enabled (config = 0x09)
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_exclude, sizeof(sda_srf_exclude), 0,
                                         sizeof(sda_srf_exclude), kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
              nan_sda_ignore);
    // kOtherNmi is not in Exclude list -> passed (nan_sda_publish)
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_exclude, sizeof(sda_srf_exclude), 0,
                                         sizeof(sda_srf_exclude), kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 0, kOtherNmi),
              nan_sda_publish);
    // When SRF is disabled in config (config = 0x01), kLocalNmi is still passed (nan_sda_publish)
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_exclude, sizeof(sda_srf_exclude), 0,
                                         sizeof(sda_srf_exclude), kTargetServiceId,
                                         0x01 /* Subscriber, SRF disabled */, 0, kLocalNmi),
              nan_sda_publish);

    // 2. Include MAC List with 3 MACs (srf_ctrl = 0x02: MAC list, Include mode)
    const uint8_t sda_srf_include[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, // Service ID
        0x01, 0x00, 0x08,                   // Publish | NAN_SRV_CTRL_RESP_FILTER (0x08)
        19,                                 // srf_len: 1 (ctrl) + 18 (3 MACs)
        0x02,                               // srf_ctrl: MAC list, Include mode
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // MAC 1
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // MAC 2 (kLocalNmi)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66  // MAC 3
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_include, sizeof(sda_srf_include), 0,
                                         sizeof(sda_srf_include), kTargetServiceId,
                                         0x09, 0, kLocalNmi),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_include, sizeof(sda_srf_include), 0,
                                         sizeof(sda_srf_include), kTargetServiceId,
                                         0x09, 0, kOtherNmi),
              nan_sda_ignore);

    // 3. Empty MAC list (srf_len = 1, 0 MACs): Exclude matches all, Include matches none
    const uint8_t sda_empty_mac_exclude[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08,
        1, 0x00 /* MAC list, Exclude, 0 MACs */
    };
    const uint8_t sda_empty_mac_include[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08,
        1, 0x02 /* MAC list, Include, 0 MACs */
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_empty_mac_exclude, sizeof(sda_empty_mac_exclude), 0,
                                         sizeof(sda_empty_mac_exclude), kTargetServiceId,
                                         0x09, 0, kLocalNmi),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_empty_mac_include, sizeof(sda_empty_mac_include), 0,
                                         sizeof(sda_empty_mac_include), kTargetServiceId,
                                         0x09, 0, kLocalNmi),
              nan_sda_ignore);

    // 4. Follow-up SDA (msg_type = 2) with an excluding SRF (srv_ctrl = 0x0a)
    const uint8_t followup_srf_exclude[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
        0x01, 0x02,
        0x0a,                               // Follow-up (0x02) | NAN_SRV_CTRL_RESP_FILTER (0x08)
        0x07, 0x00,                         // srf_len = 7, MAC list, Exclude mode
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55  // kLocalNmi
    };
    EXPECT_EQ(apf_internal_match_nan_sda(followup_srf_exclude, sizeof(followup_srf_exclude), 0,
                                         sizeof(followup_srf_exclude), kTargetServiceId,
                                         0x08 /* Publisher + SRF enable */, 0, kLocalNmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(followup_srf_exclude, sizeof(followup_srf_exclude), 0,
                                         sizeof(followup_srf_exclude), kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(followup_srf_exclude, sizeof(followup_srf_exclude), 0,
                                         sizeof(followup_srf_exclude), kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 0, kOtherNmi),
              nan_sda_follow_up);

    // 5. MAC list with trailing bytes (< 6 bytes ignored per wpa_supplicant nan_srf_match):
    // 1 complete MAC (kLocalNmi) + 2 trailing bytes (content_len = 8, srf_len = 9)
    const uint8_t sda_mac_trailing_exclude[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08,
        0x09, 0x00,                         // srf_len = 9, MAC list, Exclude mode
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // Complete MAC (kLocalNmi)
        0xde, 0xad                          // 2 trailing bytes (ignored)
    };
    const uint8_t sda_mac_trailing_include[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08,
        0x09, 0x02,                         // srf_len = 9, MAC list, Include mode
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // Complete MAC (kLocalNmi)
        0xde, 0xad                          // 2 trailing bytes (ignored)
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_mac_trailing_exclude, sizeof(sda_mac_trailing_exclude),
                                         0, sizeof(sda_mac_trailing_exclude), kTargetServiceId,
                                         0x09, 0, kLocalNmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_mac_trailing_exclude, sizeof(sda_mac_trailing_exclude),
                                         0, sizeof(sda_mac_trailing_exclude), kTargetServiceId,
                                         0x09, 0, kOtherNmi),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_mac_trailing_include, sizeof(sda_mac_trailing_include),
                                         0, sizeof(sda_mac_trailing_include), kTargetServiceId,
                                         0x09, 0, kLocalNmi),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_mac_trailing_include, sizeof(sda_mac_trailing_include),
                                         0, sizeof(sda_mac_trailing_include), kTargetServiceId,
                                         0x09, 0, kOtherNmi),
              nan_sda_ignore);
}

TEST(ApfSdaTest, SrfBloomFilterAllHashIndicesAndModes) {
    const uint8_t listed_nmi[6] = {0x1a, 0xca, 0x57, 0x00, 0x00, 0x01};

    // 1. bf_idx = 0 (j = 0..3): 4-byte Bloom filter for listed_nmi (1a:ca:57:00:00:01)
    // Hashes: 0xf68b, 0xfd3f, 0xe7a2, 0xec16 -> bits 11, 31, 2, 22 -> {0x04, 0x08, 0x40, 0x80}
    const uint8_t sda_bf_idx0_exclude[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
        0x01, 0x00, 0x08,
        5,    // srf_len: 1 (ctrl) + 4 (Bloom filter)
        0x01, // srf_ctrl: Bloom filter (bit 0=1), Exclude (bit 1=0), bf_idx = 0
        0x04, 0x08, 0x40, 0x80
    };
    const uint8_t sda_bf_idx0_include[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
        0x01, 0x00, 0x08,
        5,
        0x03, // srf_ctrl: Bloom filter (bit 0=1), Include (bit 1=1), bf_idx = 0
        0x04, 0x08, 0x40, 0x80
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_bf_idx0_exclude, sizeof(sda_bf_idx0_exclude), 0,
                                         sizeof(sda_bf_idx0_exclude), kTargetServiceId,
                                         0x09, 0, listed_nmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_bf_idx0_exclude, sizeof(sda_bf_idx0_exclude), 0,
                                         sizeof(sda_bf_idx0_exclude), kTargetServiceId,
                                         0x09, 0, kLocalNmi),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_bf_idx0_include, sizeof(sda_bf_idx0_include), 0,
                                         sizeof(sda_bf_idx0_include), kTargetServiceId,
                                         0x09, 0, listed_nmi),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_bf_idx0_include, sizeof(sda_bf_idx0_include), 0,
                                         sizeof(sda_bf_idx0_include), kTargetServiceId,
                                         0x09, 0, kLocalNmi),
              nan_sda_ignore);

    // 2. Test all 4 bf_idx values (0, 1, 2, 3) on an 8-byte (64-bit) Bloom filter for kLocalNmi
    for (uint8_t bf_idx = 0; bf_idx < 4; bf_idx++) {
        uint8_t sda_bf[9 + 2 + 8] = {
            0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
            0x01, 0x00, 0x08,
            9, // srf_len: 1 + 8
            static_cast<uint8_t>((static_cast<uint32_t>(bf_idx) << 2u) | 0x03u),
            0, 0, 0, 0, 0, 0, 0, 0
        };
        uint8_t* bf = &sda_bf[11];
        for (uint8_t j = static_cast<uint8_t>(4 * bf_idx);
             j < static_cast<uint8_t>(4 * (bf_idx + 1)); j++) {
            const uint8_t a_j_x[7] = {
                j, kLocalNmi[0], kLocalNmi[1], kLocalNmi[2],
                kLocalNmi[3], kLocalNmi[4], kLocalNmi[5]
            };
            const uint32_t bit = ((~wpa_supplicant_ieee80211_crc32(a_j_x, 7)) & 0xFFFFu) % 64u;
            bf[bit / 8u] |= static_cast<uint8_t>(1u << (bit % 8u));
        }

        // Matches kLocalNmi at the matching bf_idx, rejects kOtherNmi and mismatched bf_idx
        EXPECT_EQ(apf_internal_match_nan_sda(sda_bf, sizeof(sda_bf), 0, sizeof(sda_bf),
                                             kTargetServiceId, 0x09, 0, kLocalNmi),
                  nan_sda_publish);
        EXPECT_EQ(apf_internal_match_nan_sda(sda_bf, sizeof(sda_bf), 0, sizeof(sda_bf),
                                             kTargetServiceId, 0x09, 0, kOtherNmi),
                  nan_sda_ignore);

        const uint8_t wrong_idx = bf_idx ^ 1u;
        sda_bf[10] = static_cast<uint8_t>((static_cast<uint32_t>(wrong_idx) << 2u) | 0x03u);
        EXPECT_EQ(apf_internal_match_nan_sda(sda_bf, sizeof(sda_bf), 0, sizeof(sda_bf),
                                             kTargetServiceId, 0x09, 0, kLocalNmi),
                  nan_sda_ignore);
    }

    // 3. Direct unit check of apf_nan_check_bloom_filter edge cases
    const uint8_t dummy_bf[4] = {0xff, 0xff, 0xff, 0xff};
    EXPECT_FALSE(apf_nan_check_bloom_filter(kLocalNmi, dummy_bf, 0 /* bf_len = 0 */, 0));
    EXPECT_FALSE(apf_nan_check_bloom_filter(nullptr, dummy_bf, sizeof(dummy_bf), 0));
    EXPECT_FALSE(apf_nan_check_bloom_filter(kLocalNmi, nullptr, sizeof(dummy_bf), 0));
    // bf_len * 8 would wrap to 0 (division by zero) without the bf_len <= 255 guard
    EXPECT_FALSE(apf_nan_check_bloom_filter(kLocalNmi, dummy_bf, 0x20000000u, 0));
    EXPECT_FALSE(apf_nan_check_bloom_filter(kLocalNmi, dummy_bf, 256u, 0));
}

TEST(ApfSdaTest, MatchBloomFilterSrfAcrossAllCrc32Modes) {
    // Include-mode Bloom filter SRF (bf_idx = 0) containing only listed_nmi
    // (bits 2, 11, 22, 31), evaluated end-to-end through apf_internal_match_nan_sda()
    // with the table, bitwise, and external (firmware hook) CRC-32 implementations.
    const uint8_t listed_nmi[6] = {0x1a, 0xca, 0x57, 0x00, 0x00, 0x01};
    const uint8_t sda_bf_include[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
        0x01, 0x00, 0x08,
        5,    // srf_len: 1 (ctrl) + 4 (Bloom filter)
        0x03, // srf_ctrl: Bloom filter (bit 0=1), Include (bit 1=1), bf_idx = 0
        0x04, 0x08, 0x40, 0x80
    };

    EXPECT_EQ(apf_internal_match_nan_sda(sda_bf_include, sizeof(sda_bf_include), 0,
                                         sizeof(sda_bf_include), kTargetServiceId,
                                         0x09, 0, listed_nmi),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_bf_include, sizeof(sda_bf_include), 0,
                                         sizeof(sda_bf_include), kTargetServiceId,
                                         0x09, 0, kLocalNmi),
              nan_sda_ignore);

    EXPECT_EQ(crc_mode_bitwise::apf_internal_match_nan_sda(
                  sda_bf_include, sizeof(sda_bf_include), 0, sizeof(sda_bf_include),
                  kTargetServiceId, 0x09, 0, listed_nmi),
              crc_mode_bitwise::nan_sda_publish);
    EXPECT_EQ(crc_mode_bitwise::apf_internal_match_nan_sda(
                  sda_bf_include, sizeof(sda_bf_include), 0, sizeof(sda_bf_include),
                  kTargetServiceId, 0x09, 0, kLocalNmi),
              crc_mode_bitwise::nan_sda_ignore);

    crc_mode_custom::g_custom_crc32_call_count = 0;
    EXPECT_EQ(crc_mode_custom::apf_internal_match_nan_sda(
                  sda_bf_include, sizeof(sda_bf_include), 0, sizeof(sda_bf_include),
                  kTargetServiceId, 0x09, 0, listed_nmi),
              crc_mode_custom::nan_sda_publish);
    EXPECT_EQ(crc_mode_custom::g_custom_crc32_call_count, 4u);
    EXPECT_EQ(crc_mode_custom::apf_internal_match_nan_sda(
                  sda_bf_include, sizeof(sda_bf_include), 0, sizeof(sda_bf_include),
                  kTargetServiceId, 0x09, 0, kLocalNmi),
              crc_mode_custom::nan_sda_ignore);
}

TEST(ApfSdaTest, AllOptionalFieldsAndControlFlagsCombinations) {
    // SDA with ALL optional fields and control flags enabled simultaneously:
    // srv_ctrl = Publish (0x00)
    //          | NAN_SRV_CTRL_MATCHING_FILTER (0x04)
    //          | NAN_SRV_CTRL_RESP_FILTER (0x08)
    //          | NAN_SRV_CTRL_SRV_INFO (0x10)
    //          | NAN_SRV_CTRL_DISCOVERY_RANGE_LIMITED (0x20)
    //          | NAN_SRV_CTRL_BINDING_BITMAP (0x40)
    //          = 0x7c
    const uint8_t sda_all_opts[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, // Service ID (6B)
        0x03,                               // Instance ID (1B)
        0x00,                               // Requestor Instance ID (1B)
        0x7c,                               // Service Control: 0x04 | 0x08 | 0x10 | 0x20 | 0x40
        0x12, 0x34,                         // Binding Bitmap (2B)
        0x04, 0x01, 0xaa, 0x01, 0xbb,       // Matching Filter: len=4, two 1-byte LV pairs
        0x07, 0x02,                         // SRF: len=7, srf_ctrl=0x02 (MAC list, Include)
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // SRF MAC: kLocalNmi
        0x04, 0xde, 0xad, 0xbe, 0xef        // Service Specific Info (SSI): len=4, payload
    };

    // Matches when SRF is enabled and local_nmi is in the Include list
    EXPECT_EQ(apf_internal_match_nan_sda(sda_all_opts, sizeof(sda_all_opts), 0,
                                         sizeof(sda_all_opts), kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
              nan_sda_publish);
    // Rejects when SRF is enabled and local_nmi is not in the Include list
    EXPECT_EQ(apf_internal_match_nan_sda(sda_all_opts, sizeof(sda_all_opts), 0,
                                         sizeof(sda_all_opts), kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 0, kOtherNmi),
              nan_sda_ignore);
    // Matches when SRF is disabled in config, even for an NMI that is not in the Include
    // list (still traverses SRF and validates SSI bounds)
    EXPECT_EQ(apf_internal_match_nan_sda(sda_all_opts, sizeof(sda_all_opts), 0,
                                         sizeof(sda_all_opts), kTargetServiceId,
                                         0x01 /* Subscriber, SRF disabled */, 0, kOtherNmi),
              nan_sda_publish);

    // SDA with zero-length Matching Filter (flen = 0) and zero-length SSI (ssi_len = 0)
    const uint8_t sda_zero_len_opts[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
        0x01, 0x00,
        0x14, // Publish | NAN_SRV_CTRL_MATCHING_FILTER (0x04) | NAN_SRV_CTRL_SRV_INFO (0x10)
        0x00, // Matching Filter len = 0
        0x00  // SSI len = 0
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_zero_len_opts, sizeof(sda_zero_len_opts), 0,
                                         sizeof(sda_zero_len_opts), kTargetServiceId,
                                         0x01, 0, nullptr),
              nan_sda_publish);
}

TEST(ApfSdaTest, MalformedLengthsAndTruncationBounds) {
    const uint8_t valid_sda[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x00
    };

    // 1. Header shorter than 9 bytes (0, 5, and 8 bytes) -> nan_sda_ignore (per nan_de_rx_sda)
    EXPECT_EQ(apf_internal_match_nan_sda(valid_sda, sizeof(valid_sda), 0, 0,
                                         kTargetServiceId, 0x01, 0, nullptr),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(valid_sda, sizeof(valid_sda), 0, 5,
                                         kTargetServiceId, 0x01, 0, nullptr),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(valid_sda, sizeof(valid_sda), 0, 8,
                                         kTargetServiceId, 0x01, 0, nullptr),
              nan_sda_ignore);

    // 2. Packet offset / length out-of-bounds and uint32_t overflow guards -> nan_sda_truncated
    EXPECT_EQ(apf_internal_match_nan_sda(valid_sda, sizeof(valid_sda), 10 /* sda_ofs > len */, 9,
                                         kTargetServiceId, 0x01, 0, nullptr),
              nan_sda_truncated);
    EXPECT_EQ(apf_internal_match_nan_sda(valid_sda, sizeof(valid_sda), 1, 9 /* 1 + 9 > 9 */,
                                         kTargetServiceId, 0x01, 0, nullptr),
              nan_sda_truncated);
    EXPECT_EQ(apf_internal_match_nan_sda(valid_sda, sizeof(valid_sda), 0xFFFFFFFCu, 9,
                                         kTargetServiceId, 0x01, 0, nullptr),
              nan_sda_truncated);
    // Only sda_len is too large: a naive sda_ofs + sda_len (5 + 0xFFFFFFFD) wraps to 2
    EXPECT_EQ(apf_internal_match_nan_sda(valid_sda, sizeof(valid_sda), 5, 0xFFFFFFFDu,
                                         kTargetServiceId, 0x01, 0, nullptr),
              nan_sda_truncated);

    // 3. Truncated Binding Bitmap (srv_ctrl = 0x40 requires 2 bytes after 9-byte header) -> nan_sda_ignore
    const uint8_t sda_trunc_bitmap[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x40, 0x12 /* only 1 byte */
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_trunc_bitmap, 9, 0, 9,
                                         kTargetServiceId, 0x01, 0, nullptr),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_trunc_bitmap, sizeof(sda_trunc_bitmap), 0,
                                         sizeof(sda_trunc_bitmap), kTargetServiceId,
                                         0x01, 0, nullptr),
              nan_sda_ignore);

    // 4. Truncated Matching Filter (srv_ctrl = 0x04) -> nan_sda_ignore
    // Exact 9-byte buffer so that an out-of-bounds read of the missing length byte is visible
    // to ASan.
    const uint8_t sda_mf_no_len[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x04 /* missing length byte */
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_mf_no_len, sizeof(sda_mf_no_len), 0,
                                         sizeof(sda_mf_no_len), kTargetServiceId,
                                         0x01, 0, nullptr),
              nan_sda_ignore);
    const uint8_t sda_trunc_mf[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x04,
        0x05, 0x01, 0x02 /* claims 5 bytes, only 2 present */
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_trunc_mf, sizeof(sda_trunc_mf), 0,
                                         sizeof(sda_trunc_mf), kTargetServiceId,
                                         0x01, 0, nullptr),
              nan_sda_ignore);

    // 4b. Field overrun within sda_len when packet_len > sda_len (validates bounds check is
    // against sda_len rather than packet_len)
    const uint8_t sda_field_overrun_in_larger_packet[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x04,
        0x06, 0xaa, 0xbb,                   // SDA ends at sda_len=12, but MF claims 6 bytes
        0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22  // Subsequent bytes in packet outside sda_len
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_field_overrun_in_larger_packet,
                                         sizeof(sda_field_overrun_in_larger_packet) /* 18 */,
                                         0, 12 /* sda_len */, kTargetServiceId,
                                         0x01, 0, nullptr),
              nan_sda_ignore);

    // 5. Malformed / truncated SRF (srv_ctrl = 0x08) -> nan_sda_ignore
    // 5a. Missing srf_len byte
    const uint8_t sda_srf_no_len[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_no_len, sizeof(sda_srf_no_len), 0,
                                         sizeof(sda_srf_no_len), kTargetServiceId,
                                         0x01 /* even with SRF disabled */, 0, nullptr),
              nan_sda_ignore);

    // 5b. srf_len == 0 (missing srf_ctrl byte)
    const uint8_t sda_srf_zero_len[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_zero_len, sizeof(sda_srf_zero_len), 0,
                                         sizeof(sda_srf_zero_len), kTargetServiceId,
                                         0x01 /* even with SRF disabled */, 0, nullptr),
              nan_sda_ignore);

    // 5c. srf_len overflows sda_len (rejected both when srf_enable=0 and srf_enable=1)
    const uint8_t sda_srf_overflow[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08,
        0x07, 0x00, 0x02, 0x11 /* claims 7 bytes, only 3 present */
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_overflow, sizeof(sda_srf_overflow), 0,
                                         sizeof(sda_srf_overflow), kTargetServiceId,
                                         0x01 /* SRF disabled */, 0, nullptr),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_overflow, sizeof(sda_srf_overflow), 0,
                                         sizeof(sda_srf_overflow), kTargetServiceId,
                                         0x09 /* SRF enabled */, 0, kLocalNmi),
              nan_sda_ignore);

    // 5d. MAC list with < 6 bytes (5 bytes -> 0 complete MACs; Exclude matches, Include rejects)
    const uint8_t sda_srf_short_mac_exclude[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08,
        0x06, 0x00, 0x02, 0x11, 0x22, 0x33, 0x44 /* 5 MAC bytes (Exclude) */
    };
    const uint8_t sda_srf_short_mac_include[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08,
        0x06, 0x02, 0x02, 0x11, 0x22, 0x33, 0x44 /* 5 MAC bytes (Include) */
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_short_mac_exclude,
                                         sizeof(sda_srf_short_mac_exclude), 0,
                                         sizeof(sda_srf_short_mac_exclude), kTargetServiceId,
                                         0x09, 0, kLocalNmi),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_short_mac_include,
                                         sizeof(sda_srf_short_mac_include), 0,
                                         sizeof(sda_srf_short_mac_include), kTargetServiceId,
                                         0x09, 0, kLocalNmi),
              nan_sda_ignore);

    // 5e. Empty Bloom filter (srf_len = 1 -> content_len = 0) -> nan_sda_ignore
    const uint8_t sda_srf_empty_bf_excl[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08, 0x01, 0x01
    };
    const uint8_t sda_srf_empty_bf_incl[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08, 0x01, 0x03
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_empty_bf_excl, sizeof(sda_srf_empty_bf_excl), 0,
                                         sizeof(sda_srf_empty_bf_excl), kTargetServiceId,
                                         0x09, 0, kLocalNmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_empty_bf_incl, sizeof(sda_srf_empty_bf_incl), 0,
                                         sizeof(sda_srf_empty_bf_incl), kTargetServiceId,
                                         0x09, 0, kLocalNmi),
              nan_sda_ignore);

    // 5f. Null local_nmi when SRF is enabled -> nan_sda_error_program
    const uint8_t sda_valid_srf[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08,
        0x07, 0x02, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_valid_srf, sizeof(sda_valid_srf), 0,
                                         sizeof(sda_valid_srf), kTargetServiceId,
                                         0x09 /* SRF enabled */, 0, nullptr),
              nan_sda_error_program);

    // 6. Service Specific Info (srv_ctrl & 0x10) is app payload and is never read: an SDA whose
    // SSI is missing or truncated still passes.
    const uint8_t sda_ssi_no_len[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x10 /* NAN_SRV_CTRL_SRV_INFO */
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_ssi_no_len, sizeof(sda_ssi_no_len), 0,
                                         sizeof(sda_ssi_no_len), kTargetServiceId,
                                         0x01, 0, nullptr),
              nan_sda_publish);

    // Truncated SSI following a valid SRF: the SSI is never read, so the SDA passes
    const uint8_t sda_srf_then_trunc_ssi[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00,
        0x18,                               // Publish | SRF (0x08) | SSI (0x10)
        0x07, 0x00,                         // Valid 7-byte Exclude SRF
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x04, 0xaa, 0xbb                    // Truncated SSI: claims 4 bytes, only 2 present
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_srf_then_trunc_ssi, sizeof(sda_srf_then_trunc_ssi), 0,
                                         sizeof(sda_srf_then_trunc_ssi), kTargetServiceId,
                                         0x01 /* SRF disabled */, 0, nullptr),
              nan_sda_publish);
}

TEST(ApfSdaTest, SubscriberWithSolicitedBitRejectsSubscribe) {
    // A Subscriber never answers a Subscribe, even with config bit 2 set
    // (bit 2 only applies to a Publisher).
    const uint8_t subscribe_sda[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x01 /* Subscribe */
    };
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_sda, sizeof(subscribe_sda), 0,
                                         sizeof(subscribe_sda), kTargetServiceId,
                                         0x05 /* Subscriber + bit 2 */, 0, nullptr),
              nan_sda_ignore);
}

TEST(ApfSdaTest, SrfDisabledIgnoresMembershipWithNonNullNmi) {
    // Exclude list containing kLocalNmi: excluded only when SRF filtering is enabled.
    const uint8_t sda_exclude_local[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00,
        0x08,                               // Publish | SRF
        0x07, 0x00,                         // srf_len = 7, MAC list, Exclude
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55  // kLocalNmi
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_exclude_local, sizeof(sda_exclude_local), 0,
                                         sizeof(sda_exclude_local), kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_exclude_local, sizeof(sda_exclude_local), 0,
                                         sizeof(sda_exclude_local), kTargetServiceId,
                                         0x01 /* Subscriber, SRF disabled */, 0, kLocalNmi),
              nan_sda_publish);

    // Include list without kLocalNmi: rejected only when SRF filtering is enabled.
    const uint8_t sda_include_other[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00,
        0x08,                               // Publish | SRF
        0x07, 0x02,                         // srf_len = 7, MAC list, Include
        0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01  // kOtherNmi
    };
    EXPECT_EQ(apf_internal_match_nan_sda(sda_include_other, sizeof(sda_include_other), 0,
                                         sizeof(sda_include_other), kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(sda_include_other, sizeof(sda_include_other), 0,
                                         sizeof(sda_include_other), kTargetServiceId,
                                         0x01 /* Subscriber, SRF disabled */, 0, kLocalNmi),
              nan_sda_publish);
}

TEST(ApfSdaTest, SrfMacListComparesEveryByteAndEntry) {
    // 1. An entry that differs from kLocalNmi in exactly one byte does not match it.
    for (uint32_t pos = 0; pos < 6u; pos++) {
        uint8_t sda[] = {
            0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00,
            0x08,                               // Publish | SRF
            0x07, 0x02,                         // srf_len = 7, MAC list, Include
            0x02, 0x11, 0x22, 0x33, 0x44, 0x55  // kLocalNmi, one byte flipped below
        };
        sda[11u + pos] = static_cast<uint8_t>(sda[11u + pos] ^ 0x01u);
        EXPECT_EQ(apf_internal_match_nan_sda(sda, sizeof(sda), 0, sizeof(sda), kTargetServiceId,
                                             0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
                  nan_sda_ignore) << "Include, byte " << pos;
        sda[10] = 0x00;  // Exclude
        EXPECT_EQ(apf_internal_match_nan_sda(sda, sizeof(sda), 0, sizeof(sda), kTargetServiceId,
                                             0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
                  nan_sda_publish) << "Exclude, byte " << pos;
    }

    // 2. Largest MAC list: srf_len = 255 (control byte, 42 MACs, 2 trailing bytes), with
    // kLocalNmi as the last complete entry.
    uint8_t long_sda[9 + 1 + 255];
    const uint8_t header[9] = {0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08};
    for (uint32_t i = 0; i < 9u; i++) long_sda[i] = header[i];
    long_sda[9] = 255;    // srf_len
    long_sda[10] = 0x02;  // MAC list, Include
    for (uint32_t m = 0; m < 41u; m++) {
        for (uint32_t b = 0; b < 6u; b++) long_sda[11u + m * 6u + b] = kOtherNmi[b];
        long_sda[11u + m * 6u + 5u] = static_cast<uint8_t>(m);
    }
    for (uint32_t b = 0; b < 6u; b++) long_sda[11u + 41u * 6u + b] = kLocalNmi[b];
    long_sda[11u + 42u * 6u] = 0xee;       // 2 trailing bytes (ignored)
    long_sda[11u + 42u * 6u + 1u] = 0xee;
    EXPECT_EQ(apf_internal_match_nan_sda(long_sda, sizeof(long_sda), 0, sizeof(long_sda),
                                         kTargetServiceId, 0x09 /* Subscriber + SRF enable */,
                                         0, kLocalNmi),
              nan_sda_publish);
    long_sda[10] = 0x00;  // Exclude
    EXPECT_EQ(apf_internal_match_nan_sda(long_sda, sizeof(long_sda), 0, sizeof(long_sda),
                                         kTargetServiceId, 0x09 /* Subscriber + SRF enable */,
                                         0, kLocalNmi),
              nan_sda_ignore);
}

TEST(ApfSdaTest, SrfMacListIgnoresTrailingPartialEntry) {
    // SRF with 5 MAC bytes (02:11:22:33:44, a partial kLocalNmi). The next byte in the SDA is
    // the SSI length byte, 0x55 == kLocalNmi[5]. Reading a 6th byte would see kLocalNmi.
    uint8_t sda[9 + 1 + 6 + 1 + 0x55];
    const uint8_t prefix[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00,
        0x18,                               // Publish | SRF (0x08) | SSI (0x10)
        0x06, 0x00,                         // srf_len = 6, MAC list, Exclude
        0x02, 0x11, 0x22, 0x33, 0x44,       // 5 trailing bytes: no complete MAC
        0x55                                // SSI length = 0x55
    };
    for (size_t i = 0; i < sizeof(prefix); i++) sda[i] = prefix[i];
    for (size_t i = sizeof(prefix); i < sizeof(sda); i++) sda[i] = 0x5a;
    EXPECT_EQ(apf_internal_match_nan_sda(sda, sizeof(sda), 0, sizeof(sda), kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
              nan_sda_publish);
    sda[10] = 0x02;  // Include
    EXPECT_EQ(apf_internal_match_nan_sda(sda, sizeof(sda), 0, sizeof(sda), kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
              nan_sda_ignore);
}

TEST(ApfSdaTest, BloomFilterRequiresAllFourBits) {
    // kLocalNmi with bf_idx = 0 and a 4-byte filter hashes to bits {3, 10, 23, 30}:
    // the full filter is {0x08, 0x04, 0x80, 0x40}. Clearing any one of the 4 bits means
    // kLocalNmi is not in the filter.
    const uint8_t full_bf[4] = {0x08, 0x04, 0x80, 0x40};
    for (uint32_t clear = 0; clear <= 4u; clear++) {
        uint8_t sda[] = {
            0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00,
            0x08,         // Publish | SRF
            0x05, 0x01,   // srf_len = 5, Bloom filter, Exclude, bf_idx = 0
            full_bf[0], full_bf[1], full_bf[2], full_bf[3]
        };
        if (clear < 4u) sda[11u + clear] = 0x00;  // clear = 4: keep all 4 bits
        const bool in_filter = (clear == 4u);
        EXPECT_EQ(apf_internal_match_nan_sda(sda, sizeof(sda), 0, sizeof(sda), kTargetServiceId,
                                             0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
                  in_filter ? nan_sda_ignore : nan_sda_publish) << "Exclude, cleared byte " << clear;
        sda[10] = 0x03;  // Bloom filter, Include, bf_idx = 0
        EXPECT_EQ(apf_internal_match_nan_sda(sda, sizeof(sda), 0, sizeof(sda), kTargetServiceId,
                                             0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
                  in_filter ? nan_sda_publish : nan_sda_ignore) << "Include, cleared byte " << clear;
    }
}

TEST(ApfSdaTest, LargestBloomFilterMatches) {
    // srf_len = 255: control byte + 254-byte (2032-bit) Bloom filter with bf_idx = 2. Pins the
    // upper bound of the bf_len guard in apf_nan_check_bloom_filter() from below.
    uint8_t sda[9 + 1 + 255] = {0};
    for (uint32_t i = 0; i < 6u; i++) sda[i] = kTargetServiceId[i];
    sda[6] = 0x01;   // Instance ID
    sda[8] = 0x08;   // Publish | SRF
    sda[9] = 255;    // srf_len
    sda[10] = 0x0b;  // Bloom filter, Include, bf_idx = 2
    uint8_t* const bf = &sda[11];
    // Empty filter: kLocalNmi is not in it.
    EXPECT_EQ(apf_internal_match_nan_sda(sda, sizeof(sda), 0, sizeof(sda), kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
              nan_sda_ignore);
    for (uint8_t j = 8; j < 12; j++) {
        const uint8_t a_j_x[7] = {j, kLocalNmi[0], kLocalNmi[1], kLocalNmi[2],
                                  kLocalNmi[3], kLocalNmi[4], kLocalNmi[5]};
        const uint32_t bit =
            ((~wpa_supplicant_ieee80211_crc32(a_j_x, 7)) & 0xFFFFu) % (254u * 8u);
        bf[bit / 8u] |= static_cast<uint8_t>(1u << (bit % 8u));
    }
    EXPECT_EQ(apf_internal_match_nan_sda(sda, sizeof(sda), 0, sizeof(sda), kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
              nan_sda_publish);
    sda[10] = 0x09;  // Bloom filter, Exclude, bf_idx = 2
    EXPECT_EQ(apf_internal_match_nan_sda(sda, sizeof(sda), 0, sizeof(sda), kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 0, kLocalNmi),
              nan_sda_ignore);

    // Direct call at the guard's boundary: a 255-byte all-ones filter contains every NMI.
    uint8_t all_ones[255];
    for (size_t i = 0; i < sizeof(all_ones); i++) all_ones[i] = 0xff;
    EXPECT_TRUE(apf_nan_check_bloom_filter(kLocalNmi, all_ones, 255u, 0));
}

TEST(ApfSdaTest, OptionalFieldsBoundedBySdaLenNotPacketLen) {
    // Each SDA below is followed by more packet bytes, so a field that overruns sda_len still
    // fits in packet_len. The SDA must be rejected.
    // 1. Binding Bitmap: 1 of 2 bytes inside sda_len = 10.
    const uint8_t bitmap_pkt[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x40, 0x12,
        0x34, 0x56, 0x78                    // outside sda_len
    };
    EXPECT_EQ(apf_internal_match_nan_sda(bitmap_pkt, sizeof(bitmap_pkt), 0, 10, kTargetServiceId,
                                         0x01, 0, nullptr),
              nan_sda_ignore);
    // 2. SRF: srf_len = 3, but only 2 bytes inside sda_len = 12.
    const uint8_t srf_pkt[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x08, 0x03, 0x00, 0x02,
        0x11, 0x22, 0x33                    // outside sda_len
    };
    EXPECT_EQ(apf_internal_match_nan_sda(srf_pkt, sizeof(srf_pkt), 0, 12, kTargetServiceId,
                                         0x01, 0, nullptr),
              nan_sda_ignore);
}

TEST(ApfSdaTest, ExactFitBoundaries) {
    // Optional fields that end exactly at sda_len are accepted.
    const uint8_t bitmap_only[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x40 /* Binding Bitmap */, 0x12, 0x34
    };
    EXPECT_EQ(apf_internal_match_nan_sda(bitmap_only, sizeof(bitmap_only), 0, sizeof(bitmap_only),
                                         kTargetServiceId, 0x01, 0, nullptr),
              nan_sda_publish);
    const uint8_t empty_mf[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x04 /* Matching Filter */, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(empty_mf, sizeof(empty_mf), 0, sizeof(empty_mf),
                                         kTargetServiceId, 0x01, 0, nullptr),
              nan_sda_publish);
    const uint8_t ssi_exact[] = {
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x10 /* SSI */, 0x02, 0xaa, 0xbb
    };
    EXPECT_EQ(apf_internal_match_nan_sda(ssi_exact, sizeof(ssi_exact), 0, sizeof(ssi_exact),
                                         kTargetServiceId, 0x01, 0, nullptr),
              nan_sda_publish);

    // sda_ofs == packet_len with sda_len == 0 is inside the packet: a too-short SDA (nan_sda_ignore),
    // not a packet error.
    const uint8_t pkt[9] = {0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, 0x01, 0x00, 0x00};
    EXPECT_EQ(apf_internal_match_nan_sda(pkt, sizeof(pkt), sizeof(pkt), 0, kTargetServiceId,
                                         0x01, 0, nullptr),
              nan_sda_ignore);
}

TEST(ApfSdaTest, WpaSupplicantUnsolicitedPublishSdfWithFullAttributes) {
    // Full wire-format IEEE 802.11 Wi-Fi Aware (NAN) Unsolicited Publish SDF
    // modeled on wpa_supplicant nan_de_tx_sdf() / nan_de_sdf_attrs_put()
    // (external/wpa_supplicant_8/src/common/nan_de.c): SDA (with Matching Filter and
    // Discovery Range Limited flag), SDEA (with Range Limit + WFA OUI SSI), Element
    // Container, CSIA, SCIA, DCEA and NPBA, plus Master Indication and Cluster
    // attributes, which wpa_supplicant does not emit.
    const uint8_t publish_sdf_packet[] = {
        // --- 1. IEEE 802.11 Management Action Header (24 bytes, offsets 0..23) ---
        0xd0, 0x00,                         // Frame Control: Action (0x00d0)
        0x00, 0x00,                         // Duration: 0
        0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, // DA: NAN Management Multicast Address
        0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, // SA: Peer Publisher NMI
        0x50, 0x6f, 0x9a, 0x01, 0x23, 0x45, // BSSID: NAN Cluster ID
        0x10, 0x00,                         // Sequence Control

        // --- 2. WFA NAN SDF Public Action Header (6 bytes, offsets 24..29) ---
        0x04, 0x09,                         // Category: Public (0x04), Action: Vendor (0x09)
        0x50, 0x6f, 0x9a,                   // OUI: Wi-Fi Alliance (50:6f:9a)
        0x13,                               // OUI Type: NAN SDF (0x13)

        // --- 3. NAN Attributes (offsets 30..136) ---
        // Attr 1: Master Indication (Type 0x00, Len 2, offsets 30..34)
        0x00, 0x02, 0x00, 0x40, 0x2a,

        // Attr 2: Cluster Attribute (Type 0x01, Len 13, offsets 35..50)
        0x01, 0x0d, 0x00,
        0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00, 0x40, // Anchor Master Rank (8B)
        0x00,                                           // Hop Count
        0x00, 0x00, 0x00, 0x00,                         // AMBTT

        // Attr 3: Service Descriptor Attribute (Type 0x03, Len 14, offsets 51..67)
        0x03, 0x0e, 0x00,
        // --- SDA Payload (offset 54, length 14) ---
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, // Service ID (6B)
        0x05,                               // Instance ID: 5
        0x00,                               // Requestor Instance ID: 0 (Unsolicited)
        0x24,                               // Service Control: Publish (0x00) |
                                            //   Matching Filter (0x04) |
                                            //   Discovery Range Limited (0x20)
        0x04, 0x01, 0x0a, 0x01, 0x0b,       // Matching Filter (5B): len=4, LV pairs

        // Attr 4: Service Descriptor Extension Attribute (SDEA - Type 0x0e, Len 16, offsets 68..86)
        0x0e, 0x10, 0x00,
        0x05,                               // Instance ID: 5
        0x45, 0x01,                         // SDEA Control (LE): FSD_REQ (0x0001) |
                                            //   DATA_PATH_REQ (0x0004) | SECURITY_REQ (0x0040) |
                                            //   RANGE_LIMIT (0x0100)
        0x64, 0x00, 0xc8, 0x00,             // Range Limit: Ingress 100cm, Egress 200cm
        0x07, 0x00,                         // SDEA SSI Length (LE): 7 bytes
        0x50, 0x6f, 0x9a, 0x02,             // WFA OUI + Service Protocol Type (Generic = 2)
        0xaa, 0xbb, 0xcc,                   // SDEA SSI Payload

        // Attr 5: Element Container Attribute (Type 0x1d, Len 5, offsets 87..94)
        0x1d, 0x05, 0x00,
        0x00,                               // Map ID: 0
        0x2d, 0x02, 0x00, 0x00,             // Element data

        // Attr 6: Cipher Suite Info Attribute (CSIA - Type 0x22, Len 3, offsets 95..100)
        0x22, 0x03, 0x00,
        0x00,                               // Capabilities
        0x01, 0x05,                         // Cipher Suite ID 1 (NCS-SK-128), Instance ID 5

        // Attr 7: Security Context Info Attribute (SCIA - Type 0x23, Len 20, offsets 101..123)
        0x23, 0x14, 0x00,
        0x10, 0x00, 0x01, 0x05,             // Sec Context Len (16), Type (PMKID=1), Inst ID (5)
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,

        // Attr 8: Device Capability Extension Attribute (DCEA - Type 0x2a, Len 2, offsets 124..128)
        0x2a, 0x02, 0x00,
        0x00, 0x03,                         // Pairing setup + NPK/NIK caching enabled

        // Attr 9: NAN Pairing Bootstrapping Attribute (NPBA - Type 0x2c, Len 5, offsets 129..136)
        0x2c, 0x05, 0x00,
        0x01, 0x00, 0x00, 0x02, 0x00        // Dialog token, type/status, reason, PBM
    };
    const uint32_t sda_ofs = 54;
    const uint32_t sda_len = 14;

    EXPECT_EQ(apf_internal_match_nan_sda(publish_sdf_packet, sizeof(publish_sdf_packet),
                                         sda_ofs, sda_len, kTargetServiceId,
                                         0x01 /* Subscriber */, 0, nullptr),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(publish_sdf_packet, sizeof(publish_sdf_packet),
                                         sda_ofs, sda_len, kTargetServiceId,
                                         0x00 /* Publisher */, 0, nullptr),
              nan_sda_ignore);
}

TEST(ApfSdaTest, WpaSupplicantActiveSubscribeSdfWithBloomFilterSrf) {
    // Active Subscribe SDF modeled on wpa_supplicant nan_de_sdf_attrs_put(), plus a
    // Binding Bitmap (0x40) that wpa_supplicant does not emit, a Matching Filter
    // (0x04), and a Bloom Filter SRF (0x08).
    const uint8_t listed_nmi[6] = {0x1a, 0xca, 0x57, 0x00, 0x00, 0x01};
    const uint8_t subscribe_sdf_packet[] = {
        // 802.11 Management Action Header (24B) + WFA NAN SDF Header (6B)
        0xd0, 0x00, 0x00, 0x00,
        0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00,
        0x02, 0x99, 0x88, 0x77, 0x66, 0x55,
        0x50, 0x6f, 0x9a, 0x01, 0x23, 0x45,
        0x20, 0x00,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13,

        // Attr 1: SDA (Type 0x03, Len 20, offsets 30..52; payload at offset 33, len 20)
        0x03, 0x14, 0x00,
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf, // Service ID (6B)
        0x02,                               // Subscriber Instance ID: 2
        0x00,                               // Requestor Instance ID: 0
        0x4d,                               // Service Control: Subscribe (0x01) |
                                            //   Matching Filter (0x04) | SRF (0x08) |
                                            //   Binding Bitmap (0x40)
        0x01, 0x00,                         // Binding Bitmap (2B)
        0x02, 0x01, 0xff,                   // Matching Filter (3B): len=2
        0x05,                               // SRF Length: 5 bytes
        0x03,                               // SRF Control: Bloom Filter (1) | Include (2) | bf_idx=0
        0x04, 0x08, 0x40, 0x80,             // 4-byte Bloom filter containing listed_nmi

        // Attr 2: SDEA (Type 0x0e, Len 3, offsets 53..58)
        0x0e, 0x03, 0x00,
        0x02, 0x04, 0x00                    // Instance ID 2, DATA_PATH_REQ
    };
    const uint32_t sda_ofs = 33;
    const uint32_t sda_len = 20;

    // Solicited Publisher (0x04) + SRF Enable (0x08) = 0x0c:
    // Matches listed_nmi, rejects unlisted kLocalNmi
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_sdf_packet, sizeof(subscribe_sdf_packet),
                                         sda_ofs, sda_len, kTargetServiceId,
                                         0x0c /* Solicited Publisher + SRF enable */, 0,
                                         listed_nmi),
              nan_sda_subscribe);
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_sdf_packet, sizeof(subscribe_sdf_packet),
                                         sda_ofs, sda_len, kTargetServiceId,
                                         0x0c /* Solicited Publisher + SRF enable */, 0, kLocalNmi),
              nan_sda_ignore);

    // Unsolicited-only Publisher (0x08 = Publisher, solicited=0, SRF enable=1) ignores Subscribe
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_sdf_packet, sizeof(subscribe_sdf_packet),
                                         sda_ofs, sda_len, kTargetServiceId,
                                         0x08 /* Unsolicited-only Publisher + SRF enable */, 0,
                                         listed_nmi),
              nan_sda_ignore);
}

TEST(ApfSdaTest, WpaSupplicantMergedMultiSdaFrame) {
    // Merged SDF containing 3 back-to-back SDA attributes in a single NAN frame
    // (as handled by nan_de_rx_sdf() and nan_apf_manager_capture_tx_payload()).
    const uint8_t merged_sdf_packet[] = {
        // 802.11 Management Action Header (24B) + WFA NAN SDF Header (6B) (offsets 0..29)
        0xd0, 0x00, 0x00, 0x00,
        0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00,
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x50, 0x6f, 0x9a, 0x01, 0x00, 0x00,
        0x30, 0x00,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13,

        // SDA #1 (Type 0x03, Len 9, offsets 30..41; payload at offset 33, len 9):
        // Unrelated service ID (11:22:33:44:55:66)
        0x03, 0x09, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x01, 0x00, 0x00,

        // SDA #2 (Type 0x03, Len 17, offsets 42..61; payload at offset 45, len 17):
        // Target service ID, Solicited Publish (req_instance_id = 7) + Include MAC SRF
        0x03, 0x11, 0x00,
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
        0x02, 0x07, 0x08,                   // Publish (0) | SRF (0x08), req_instance_id = 7
        0x07, 0x02,                         // SRF len=7, MAC list Include
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // kLocalNmi

        // SDA #3 (Type 0x03, Len 14, offsets 62..78; payload at offset 65, len 14):
        // Target service ID, Follow-up (0x02) + in-SDA Service Specific Info (0x10)
        0x03, 0x0e, 0x00,
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
        0x02, 0x07, 0x12,                   // Follow-up (0x02) | NAN_SRV_CTRL_SRV_INFO (0x10)
        0x04, 0xca, 0xfe, 0xba, 0xbe        // SSI: len=4, payload [ca fe ba be]
    };

    // SDA #1 (offset 33, len 9) -> nan_sda_ignore (different Service ID)
    EXPECT_EQ(apf_internal_match_nan_sda(merged_sdf_packet, sizeof(merged_sdf_packet),
                                         33, 9, kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 7, kLocalNmi),
              nan_sda_ignore);

    // SDA #2 (offset 45, len 17) -> matches Subscriber with local_inst_id=7 and kLocalNmi
    EXPECT_EQ(apf_internal_match_nan_sda(merged_sdf_packet, sizeof(merged_sdf_packet),
                                         45, 17, kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 7, kLocalNmi),
              nan_sda_publish);
    // SDA #2 rejects Subscriber with wrong local_inst_id (8) or wrong NMI
    EXPECT_EQ(apf_internal_match_nan_sda(merged_sdf_packet, sizeof(merged_sdf_packet),
                                         45, 17, kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 8, kLocalNmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(merged_sdf_packet, sizeof(merged_sdf_packet),
                                         45, 17, kTargetServiceId,
                                         0x09 /* Subscriber + SRF enable */, 7, kOtherNmi),
              nan_sda_ignore);

    // SDA #3 (offset 65, len 14) -> Follow-up with in-SDA SSI matches both Subscriber and Publisher
    EXPECT_EQ(apf_internal_match_nan_sda(merged_sdf_packet, sizeof(merged_sdf_packet),
                                         65, 14, kTargetServiceId,
                                         0x01 /* Subscriber */, 0, nullptr),
              nan_sda_follow_up);
    EXPECT_EQ(apf_internal_match_nan_sda(merged_sdf_packet, sizeof(merged_sdf_packet),
                                         65, 14, kTargetServiceId,
                                         0x00 /* Publisher */, 0, nullptr),
              nan_sda_follow_up);

    // Multi-SDA frame where the first SDA is malformed (truncated Matching Filter within its
    // sda_len = 10) and the second SDA is a valid matching Publish:
    // SDA #1 returns nan_sda_ignore (not nan_sda_truncated) so the caller continues to SDA #2,
    // which passes, mirroring wpa_supplicant's nan_de_rx_sdf() loop.
    const uint8_t malformed_first_sda_multi_pkt[] = {
        // 802.11 Management Action Header (24B) + WFA NAN SDF Header (6B) (offsets 0..29)
        0xd0, 0x00, 0x00, 0x00,
        0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00,
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x50, 0x6f, 0x9a, 0x01, 0x00, 0x00,
        0x30, 0x00,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13,

        // SDA #1 (Type 0x03, Len 10, offsets 30..42; payload at offset 33, len 10):
        // Malformed: srv_ctrl = 0x04 (Matching Filter), filter_len = 5, but 0 filter bytes in SDA
        0x03, 0x0a, 0x00,
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
        0x01, 0x00, 0x04, 0x05,

        // SDA #2 (Type 0x03, Len 9, offsets 43..54; payload at offset 46, len 9):
        // Valid Publish for kTargetServiceId
        0x03, 0x09, 0x00,
        0x68, 0x53, 0x1c, 0x27, 0x7d, 0xcf,
        0x02, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(malformed_first_sda_multi_pkt,
                                         sizeof(malformed_first_sda_multi_pkt),
                                         33, 10, kTargetServiceId,
                                         0x01 /* Subscriber */, 0, nullptr),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(malformed_first_sda_multi_pkt,
                                         sizeof(malformed_first_sda_multi_pkt),
                                         46, 9, kTargetServiceId,
                                         0x01 /* Subscriber */, 0, nullptr),
              nan_sda_publish);
}

TEST(ApfSdaTest, CapturedSdfFramesWithMatchingFilter) {
    // Captured over-the-air 802.11 NAN SDF frames containing a 24-byte
    // Matching Filter (Service ID b4:26:6b:ab:05:07).
    const uint8_t service_id[6] = {0xb4, 0x26, 0x6b, 0xab, 0x05, 0x07};

    // 1. Active Subscribe SDF (213 bytes):
    // TA=02:00:00:00:00:a1 (locally administered placeholder), inst_id=1, req_inst_id=0,
    // srv_ctrl=0x05 (Subscribe | Matching Filter), 24-byte Matching Filter, followed by
    // SDEA 0x0e, Device Capability 0x0f, and NAN Availability 0x12.
    const uint8_t active_subscribe_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0xa1, 0x50, 0x6f, 0x9a, 0x01, 0x3a, 0x56, 0x70, 0x23,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x22, 0x00, 0xb4, 0x26, 0x6b,
        0xab, 0x05, 0x07, 0x01, 0x00, 0x05, 0x18, 0x17, 0x62, 0x79, 0x74, 0x65,
        0x73, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6d,
        0x61, 0x74, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x0e, 0x34, 0x00, 0x01, 0x00,
        0x00, 0x2f, 0x00, 0x50, 0x6f, 0x9a, 0x02, 0x41, 0x72, 0x62, 0x69, 0x74,
        0x72, 0x61, 0x72, 0x79, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20, 0x66,
        0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x75, 0x62, 0x73, 0x63,
        0x72, 0x69, 0x62, 0x65, 0x20, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65,
        0x72, 0x79, 0x0f, 0x09, 0x00, 0x00, 0x09, 0x00, 0x14, 0x15, 0x22, 0x04,
        0x00, 0x0a, 0x12, 0x4c, 0x00, 0x01, 0x31, 0x00, 0x0e, 0x00, 0xe1, 0x12,
        0x18, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x11, 0x51, 0x20, 0x00, 0x00,
        0x0e, 0x00, 0xe1, 0x12, 0x18, 0x00, 0x04, 0xfc, 0xff, 0xff, 0xff, 0x11,
        0x80, 0x20, 0x00, 0x01, 0x27, 0x00, 0xea, 0x02, 0x91, 0x75, 0x03, 0x00,
        0x00, 0x80, 0x21, 0x00, 0x00, 0x51, 0xff, 0x1f, 0x00, 0x73, 0x0f, 0x00,
        0x00, 0x74, 0x03, 0x00, 0x00, 0x7c, 0x0f, 0x00, 0x00, 0x7d, 0x1f, 0x00,
        0x00, 0x7e, 0x03, 0x00, 0x00, 0x7f, 0x03, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(active_subscribe_pkt, sizeof(active_subscribe_pkt),
                                         33, 34, service_id,
                                         0x04 /* Solicited Publisher */, 0, nullptr),
              nan_sda_subscribe);
    EXPECT_EQ(apf_internal_match_nan_sda(active_subscribe_pkt, sizeof(active_subscribe_pkt),
                                         33, 34, service_id,
                                         0x00 /* Unsolicited-only Publisher */, 0, nullptr),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(active_subscribe_pkt, sizeof(active_subscribe_pkt),
                                         33, 34, service_id,
                                         0x01 /* Subscriber */, 0, nullptr),
              nan_sda_ignore);

    // 2. Solicited Publish SDF (208 bytes):
    // TA=02:00:00:00:00:a2 (locally administered placeholder), inst_id=1, req_inst_id=1,
    // srv_ctrl=0x04 (Publish | Matching Filter), 24-byte Matching Filter.
    const uint8_t solicited_publish_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0xa2, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0x40, 0x06,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x22, 0x00, 0xb4, 0x26, 0x6b,
        0xab, 0x05, 0x07, 0x01, 0x01, 0x04, 0x18, 0x17, 0x62, 0x79, 0x74, 0x65,
        0x73, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6d,
        0x61, 0x74, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x0e, 0x2f, 0x00, 0x01, 0x01,
        0x00, 0x2a, 0x00, 0x50, 0x6f, 0x9a, 0x02, 0x45, 0x78, 0x74, 0x72, 0x61,
        0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x68,
        0x65, 0x20, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x65, 0x72, 0x20,
        0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x0f, 0x09, 0x00,
        0x00, 0x09, 0x00, 0x14, 0x15, 0x22, 0x04, 0x00, 0x0a, 0x12, 0x4c, 0x00,
        0x01, 0x31, 0x00, 0x0e, 0x00, 0xe1, 0x12, 0x18, 0x00, 0x04, 0x03, 0x00,
        0x00, 0x00, 0x11, 0x51, 0x20, 0x00, 0x00, 0x0e, 0x00, 0xe1, 0x12, 0x18,
        0x00, 0x04, 0xfc, 0xff, 0xff, 0xff, 0x11, 0x80, 0x20, 0x00, 0x01, 0x27,
        0x00, 0xea, 0x02, 0x91, 0x75, 0x03, 0x00, 0x00, 0x80, 0x21, 0x00, 0x00,
        0x51, 0xff, 0x1f, 0x00, 0x73, 0x0f, 0x00, 0x00, 0x74, 0x03, 0x00, 0x00,
        0x7c, 0x0f, 0x00, 0x00, 0x7d, 0x1f, 0x00, 0x00, 0x7e, 0x03, 0x00, 0x00,
        0x7f, 0x03, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(solicited_publish_pkt, sizeof(solicited_publish_pkt),
                                         33, 34, service_id,
                                         0x01 /* Subscriber */, 1, nullptr),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(solicited_publish_pkt, sizeof(solicited_publish_pkt),
                                         33, 34, service_id,
                                         0x01 /* Subscriber */, 2 /* wrong inst_id */, nullptr),
              nan_sda_ignore);

    // 3. Follow-up SDF (199 bytes):
    // DA=02:00:00:00:00:a1, TA=02:00:00:00:00:a2 (locally administered placeholders),
    // inst_id=1, req_inst_id=1, srv_ctrl=0x06 (Follow-up | Matching Filter), 24-byte
    // Matching Filter.
    const uint8_t followup_pkt[] = {
        0xd0, 0x00, 0x3c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0xa1, 0x02, 0x00,
        0x00, 0x00, 0x00, 0xa2, 0x50, 0x6f, 0x9a, 0x01, 0x3a, 0x56, 0x80, 0x06,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x22, 0x00, 0xb4, 0x26, 0x6b,
        0xab, 0x05, 0x07, 0x01, 0x01, 0x06, 0x18, 0x17, 0x62, 0x79, 0x74, 0x65,
        0x73, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6d,
        0x61, 0x74, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x0e, 0x26, 0x00, 0x01, 0x01,
        0x00, 0x21, 0x00, 0x50, 0x6f, 0x9a, 0x02, 0x52, 0x65, 0x61, 0x64, 0x79,
        0x20, 0x5b, 0x52, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x20, 0x49, 0x64, 0x65,
        0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x3a, 0x20, 0x25, 0x73, 0x5d,
        0x0f, 0x09, 0x00, 0x00, 0x09, 0x00, 0x14, 0x15, 0x22, 0x04, 0x00, 0x0a,
        0x12, 0x4c, 0x00, 0x01, 0x31, 0x00, 0x0e, 0x00, 0xe1, 0x12, 0x18, 0x00,
        0x04, 0x03, 0x00, 0x00, 0x00, 0x11, 0x51, 0x20, 0x00, 0x00, 0x0e, 0x00,
        0xe1, 0x12, 0x18, 0x00, 0x04, 0xfc, 0xff, 0xff, 0xff, 0x11, 0x80, 0x20,
        0x00, 0x01, 0x27, 0x00, 0xea, 0x02, 0x91, 0x75, 0x03, 0x00, 0x00, 0x80,
        0x21, 0x00, 0x00, 0x51, 0xff, 0x1f, 0x00, 0x73, 0x0f, 0x00, 0x00, 0x74,
        0x03, 0x00, 0x00, 0x7c, 0x0f, 0x00, 0x00, 0x7d, 0x1f, 0x00, 0x00, 0x7e,
        0x03, 0x00, 0x00, 0x7f, 0x03, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(followup_pkt, sizeof(followup_pkt),
                                         33, 34, service_id,
                                         0x01 /* Subscriber */, 1, nullptr),
              nan_sda_follow_up);
    EXPECT_EQ(apf_internal_match_nan_sda(followup_pkt, sizeof(followup_pkt),
                                         33, 34, service_id,
                                         0x00 /* Publisher */, 1, nullptr),
              nan_sda_follow_up);
}

TEST(ApfSdaTest, CapturedSdfFramesWithInSdaSsi) {
    // Captured over-the-air 802.11 NAN SDF frames exercising Unsolicited
    // Publish, Active Subscribe, and Follow-up with in-SDA Service Specific
    // Info (Service ID 93:7e:8d:5f:bb:48).
    const uint8_t service_id[6] = {0x93, 0x7e, 0x8d, 0x5f, 0xbb, 0x48};

    // 1. Unsolicited Publish SDF (217 bytes):
    // TA=3a:35:8f:a1:46:12, inst_id=1, req_inst_id=0, srv_ctrl=0x00 Publish,
    // 9-byte SDA followed by Country Code 0x0b, SDEA 0x0e, Device
    // Capability 0x0f, two NAN Availability 0x12 attributes, Ranging Info 0x1a,
    // DCEA 0x2a, NIRA 0x2b, and Vendor Specific 0xdd.
    const uint8_t unsolicited_publish_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0x3a, 0x35,
        0x8f, 0xa1, 0x46, 0x12, 0x50, 0x6f, 0x9a, 0x01, 0x71, 0x14, 0x30, 0xb3,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x09, 0x00, 0x93, 0x7e, 0x8d,
        0x5f, 0xbb, 0x48, 0x01, 0x00, 0x00, 0x0b, 0x02, 0x00, 0x55, 0x53, 0x0e,
        0x03, 0x00, 0x01, 0x00, 0x00, 0x0f, 0x09, 0x00, 0x00, 0x09, 0x04, 0x94,
        0x15, 0x22, 0x70, 0x17, 0x08, 0x12, 0x20, 0x00, 0x03, 0x00, 0x00, 0x0e,
        0x00, 0x19, 0x12, 0x18, 0x00, 0x04, 0x03, 0x00, 0x03, 0x00, 0x11, 0x51,
        0x20, 0x00, 0x00, 0x0b, 0x00, 0x1a, 0x12, 0x18, 0x00, 0x04, 0xfc, 0xff,
        0xfc, 0xff, 0x10, 0x02, 0x12, 0x3d, 0x00, 0x03, 0x01, 0x00, 0x0b, 0x00,
        0x1a, 0x12, 0x18, 0x00, 0x04, 0xff, 0x00, 0xff, 0xff, 0x10, 0x07, 0x0b,
        0x00, 0x1a, 0x12, 0x18, 0x00, 0x04, 0xff, 0x00, 0xff, 0xff, 0x10, 0x04,
        0x0e, 0x00, 0x19, 0x12, 0x18, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00, 0x11,
        0x80, 0x20, 0x00, 0x01, 0x0e, 0x00, 0x1a, 0x12, 0x18, 0x00, 0x04, 0x00,
        0xfc, 0x00, 0x00, 0x11, 0x80, 0x20, 0x00, 0x01, 0x1a, 0x03, 0x00, 0x08,
        0xc8, 0x21, 0x2a, 0x02, 0x00, 0x05, 0x03, 0x2b, 0x11, 0x00, 0x00, 0xf3,
        0xf9, 0x00, 0xce, 0x04, 0x7e, 0xe3, 0x03, 0xdd, 0x29, 0x1f, 0xa7, 0xef,
        0x01, 0xa3, 0xbf, 0xdd, 0x13, 0x00, 0x00, 0x90, 0x4c, 0x00, 0x00, 0x04,
        0x00, 0x0b, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00,
        0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(unsolicited_publish_pkt, sizeof(unsolicited_publish_pkt),
                                         33, 9, service_id,
                                         0x01 /* Subscriber */, 5, nullptr),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(unsolicited_publish_pkt, sizeof(unsolicited_publish_pkt),
                                         33, 9, service_id,
                                         0x00 /* Publisher */, 0, nullptr),
              nan_sda_ignore);

    // 2. Active Subscribe SDF (198 bytes):
    // TA=d6:18:86:cc:15:ff, inst_id=1, req_inst_id=0, srv_ctrl=0x01 Subscribe,
    // 9-byte SDA.
    const uint8_t active_subscribe_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0xd6, 0x18,
        0x86, 0xcc, 0x15, 0xff, 0x50, 0x6f, 0x9a, 0x01, 0x71, 0x14, 0xa0, 0x3a,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x09, 0x00, 0x93, 0x7e, 0x8d,
        0x5f, 0xbb, 0x48, 0x01, 0x00, 0x01, 0x0b, 0x02, 0x00, 0x55, 0x53, 0x0e,
        0x03, 0x00, 0x01, 0x00, 0x00, 0x0f, 0x09, 0x00, 0x00, 0x04, 0x04, 0x94,
        0x15, 0x22, 0x10, 0x27, 0x08, 0x12, 0x20, 0x00, 0x16, 0x00, 0x00, 0x0e,
        0x00, 0x19, 0x12, 0x18, 0x00, 0x04, 0x03, 0x00, 0x03, 0x00, 0x11, 0x51,
        0x20, 0x00, 0x00, 0x0b, 0x00, 0x1a, 0x12, 0x18, 0x00, 0x04, 0xfc, 0xff,
        0xfc, 0xff, 0x10, 0x02, 0x12, 0x30, 0x00, 0x16, 0x01, 0x00, 0x0b, 0x00,
        0x1a, 0x12, 0x18, 0x00, 0x04, 0xff, 0xf0, 0xff, 0xff, 0x10, 0x04, 0x0e,
        0x00, 0x19, 0x12, 0x18, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00, 0x11, 0x80,
        0x20, 0x00, 0x01, 0x0e, 0x00, 0x1a, 0x12, 0x18, 0x00, 0x04, 0x00, 0x0c,
        0x00, 0x00, 0x11, 0x80, 0x20, 0x00, 0x01, 0x2a, 0x02, 0x00, 0x05, 0x03,
        0x2b, 0x11, 0x00, 0x00, 0xbb, 0xc9, 0x95, 0x25, 0x50, 0xeb, 0xb5, 0xfe,
        0x65, 0x93, 0x6a, 0xaa, 0x9a, 0x72, 0xc8, 0x26, 0xdd, 0x13, 0x00, 0x00,
        0x90, 0x4c, 0x00, 0x00, 0x04, 0x00, 0x09, 0x00, 0x00, 0x00, 0x04, 0x00,
        0x04, 0x00, 0x03, 0x00, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(active_subscribe_pkt, sizeof(active_subscribe_pkt),
                                         33, 9, service_id,
                                         0x04 /* Solicited Publisher */, 0, nullptr),
              nan_sda_subscribe);
    EXPECT_EQ(apf_internal_match_nan_sda(active_subscribe_pkt, sizeof(active_subscribe_pkt),
                                         33, 9, service_id,
                                         0x00 /* Unsolicited-only Publisher */, 0, nullptr),
              nan_sda_ignore);

    // 3. Follow-up SDF with in-SDA Service Specific Info (181 bytes):
    // TA=d6:18:86:cc:15:ff, inst_id=1, req_inst_id=1,
    // srv_ctrl=0x12 (Follow-up | NAN_SRV_CTRL_SRV_INFO), 8-byte SSI "test1234".
    const uint8_t followup_ssi_pkt[] = {
        0xd0, 0x00, 0x2c, 0x00, 0x3a, 0x35, 0x8f, 0xa1, 0x46, 0x12, 0xd6, 0x18,
        0x86, 0xcc, 0x15, 0xff, 0x50, 0x6f, 0x9a, 0x01, 0x71, 0x14, 0xa0, 0x3b,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x12, 0x00, 0x93, 0x7e, 0x8d,
        0x5f, 0xbb, 0x48, 0x01, 0x01, 0x12, 0x08, 0x74, 0x65, 0x73, 0x74, 0x31,
        0x32, 0x33, 0x34, 0x0b, 0x02, 0x00, 0x55, 0x53, 0x0f, 0x09, 0x00, 0x00,
        0x04, 0x04, 0x94, 0x15, 0x22, 0x10, 0x27, 0x08, 0x12, 0x20, 0x00, 0x16,
        0x00, 0x00, 0x0e, 0x00, 0x19, 0x12, 0x18, 0x00, 0x04, 0x03, 0x00, 0x03,
        0x00, 0x11, 0x51, 0x20, 0x00, 0x00, 0x0b, 0x00, 0x1a, 0x12, 0x18, 0x00,
        0x04, 0xfc, 0xff, 0xfc, 0xff, 0x10, 0x02, 0x12, 0x30, 0x00, 0x16, 0x01,
        0x00, 0x0b, 0x00, 0x1a, 0x12, 0x18, 0x00, 0x04, 0xff, 0xf0, 0xff, 0xff,
        0x10, 0x04, 0x0e, 0x00, 0x19, 0x12, 0x18, 0x00, 0x04, 0x00, 0x03, 0x00,
        0x00, 0x11, 0x80, 0x20, 0x00, 0x01, 0x0e, 0x00, 0x1a, 0x12, 0x18, 0x00,
        0x04, 0x00, 0x0c, 0x00, 0x00, 0x11, 0x80, 0x20, 0x00, 0x01, 0x2a, 0x02,
        0x00, 0x05, 0x03, 0xdd, 0x13, 0x00, 0x00, 0x90, 0x4c, 0x00, 0x00, 0x04,
        0x00, 0x09, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00,
        0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(followup_ssi_pkt, sizeof(followup_ssi_pkt),
                                         33, 18, service_id,
                                         0x00 /* Publisher */, 1, nullptr),
              nan_sda_follow_up);
    EXPECT_EQ(apf_internal_match_nan_sda(followup_ssi_pkt, sizeof(followup_ssi_pkt),
                                         33, 18, service_id,
                                         0x01 /* Subscriber */, 2, nullptr),
              nan_sda_follow_up);
    EXPECT_EQ(apf_internal_match_nan_sda(followup_ssi_pkt, sizeof(followup_ssi_pkt),
                                         33, 18, kTargetServiceId /* wrong service_id */,
                                         0x00 /* Publisher */, 1, nullptr),
              nan_sda_ignore);
}

TEST(ApfSdaTest, CapturedSdfFramesWithExcludeBloomFilterSrf) {
    // Captured over-the-air 802.11 NAN SDF frames between a subscriber
    // (fa:89:0e:af:db:0f / 4e:c3:b0:76:cb:2e) and a publisher
    // (2a:6d:f5:db:5f:f1) exercising Exclude Bloom Filter SRFs across
    // multiple hash indices (Service ID e8:d3:09:ba:d0:9b).
    const uint8_t service_id[6] = {0xe8, 0xd3, 0x09, 0xba, 0xd0, 0x9b};
    const uint8_t discovered_peer_nmi[6] = {0x2a, 0x6d, 0xf5, 0xdb, 0x5f, 0xf1};

    // 1. Initial Active Subscribe SDF before discovering peer (106 bytes):
    // srv_ctrl=0x01 Subscribe, no SRF.
    const uint8_t initial_subscribe_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0xfa, 0x89,
        0x0e, 0xaf, 0xdb, 0x0f, 0x50, 0x6f, 0x9a, 0x01, 0x0a, 0x1b, 0x90, 0x3b,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x09, 0x00, 0xe8, 0xd3, 0x09,
        0xba, 0xd0, 0x9b, 0x01, 0x00, 0x01, 0x0e, 0x09, 0x00, 0x01, 0x00, 0x00,
        0x04, 0x00, 0x50, 0x6f, 0x9a, 0x02, 0x0f, 0x09, 0x00, 0x00, 0x09, 0x04,
        0x14, 0x15, 0x22, 0x00, 0x00, 0x08, 0x0b, 0x02, 0x00, 0x55, 0x53, 0x1e,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x80, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x09,
        0x00, 0x00, 0x17, 0xf2, 0x10, 0x01, 0x10, 0x00, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(initial_subscribe_pkt,
                                         sizeof(initial_subscribe_pkt),
                                         33, 9, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, discovered_peer_nmi),
              nan_sda_subscribe);

    // 2. Solicited Publish reply SDF (230 bytes):
    // TA=2a:6d:f5:db:5f:f1, inst_id=1, req_inst_id=1, srv_ctrl=0x00 Publish,
    // with CSIA 0x22, SCIA 0x23, DCEA 0x2a, NIRA 0x2b, and NPBA 0x2c.
    const uint8_t solicited_publish_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0x2a, 0x6d,
        0xf5, 0xdb, 0x5f, 0xf1, 0x50, 0x6f, 0x9a, 0x01, 0x0a, 0x1b, 0x50, 0x18,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x09, 0x00, 0xe8, 0xd3, 0x09,
        0xba, 0xd0, 0x9b, 0x01, 0x01, 0x00, 0x0b, 0x02, 0x00, 0x55, 0x53, 0x0e,
        0x03, 0x00, 0x01, 0x40, 0x04, 0x0f, 0x09, 0x00, 0x00, 0x09, 0x04, 0x94,
        0x15, 0x22, 0x70, 0x17, 0x08, 0x12, 0x20, 0x00, 0x01, 0x00, 0x00, 0x0e,
        0x00, 0x19, 0x12, 0x18, 0x00, 0x04, 0x03, 0x00, 0x03, 0x00, 0x11, 0x51,
        0x20, 0x00, 0x00, 0x0b, 0x00, 0x1a, 0x12, 0x18, 0x00, 0x04, 0xfc, 0xff,
        0xfc, 0xff, 0x10, 0x02, 0x12, 0x23, 0x00, 0x01, 0x01, 0x00, 0x0e, 0x00,
        0x19, 0x12, 0x18, 0x00, 0x04, 0xff, 0xff, 0xff, 0x00, 0x11, 0x80, 0x20,
        0x00, 0x01, 0x0e, 0x00, 0x1a, 0x12, 0x18, 0x00, 0x04, 0x00, 0x00, 0x00,
        0xff, 0x11, 0x80, 0x20, 0x00, 0x01, 0x1a, 0x03, 0x00, 0x08, 0x68, 0x00,
        0x22, 0x05, 0x00, 0x04, 0x07, 0x01, 0x05, 0x01, 0x23, 0x14, 0x00, 0x10,
        0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x02, 0x00, 0x05, 0x03,
        0x2b, 0x11, 0x00, 0x00, 0x25, 0x80, 0x27, 0x87, 0x3b, 0xc5, 0x12, 0xfb,
        0x11, 0x68, 0x94, 0x0c, 0xf0, 0x00, 0x43, 0x3d, 0x2c, 0x05, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00, 0xdd, 0x13, 0x00, 0x00, 0x90, 0x4c, 0x00, 0x00,
        0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x03, 0x00,
        0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(solicited_publish_pkt,
                                         sizeof(solicited_publish_pkt),
                                         33, 9, service_id,
                                         0x01 /* Subscriber */, 1, nullptr),
              nan_sda_publish);

    // 3. Active Subscribe SDF after discovering peer (114 bytes):
    // srv_ctrl=0x09 (Subscribe | SRF), srf_len=7, srf_ctrl=0x0d (Bloom Filter,
    // Exclude, bf_idx=3), 6-byte Bloom filter [00 10 20 01 02 00]
    // (bits 12, 21, 24, 33).
    const uint8_t subscribe_bf_idx3_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0xfa, 0x89,
        0x0e, 0xaf, 0xdb, 0x0f, 0x50, 0x6f, 0x9a, 0x01, 0x0a, 0x1b, 0x20, 0x3b,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x11, 0x00, 0xe8, 0xd3, 0x09,
        0xba, 0xd0, 0x9b, 0x01, 0x00, 0x09, 0x07, 0x0d, 0x00, 0x10, 0x20, 0x01,
        0x02, 0x00, 0x0e, 0x09, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x50, 0x6f,
        0x9a, 0x02, 0x0f, 0x09, 0x00, 0x00, 0x09, 0x04, 0x14, 0x15, 0x22, 0x00,
        0x00, 0x08, 0x0b, 0x02, 0x00, 0x55, 0x53, 0x1e, 0x14, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x09, 0x00, 0x00, 0x17, 0xf2,
        0x10, 0x01, 0x10, 0x00, 0x00, 0x00
    };
    // Discovered peer NMI is in the Exclude Bloom filter -> dropped (nan_sda_ignore)
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx3_pkt,
                                         sizeof(subscribe_bf_idx3_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, discovered_peer_nmi),
              nan_sda_ignore);
    // Undiscovered publisher NMI (kLocalNmi) is not in the Exclude Bloom filter -> matched
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx3_pkt,
                                         sizeof(subscribe_bf_idx3_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, kLocalNmi),
              nan_sda_subscribe);

    // 4. Active Subscribe SDF with Exclude Bloom Filter bf_idx=2 (114 bytes):
    // srf_ctrl=0x09, 6-byte Bloom filter [04 80 40 00 00 08] (bits 2, 15, 22, 43).
    const uint8_t subscribe_bf_idx2_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0xfa, 0x89,
        0x0e, 0xaf, 0xdb, 0x0f, 0x50, 0x6f, 0x9a, 0x01, 0x0a, 0x1b, 0xb0, 0x3b,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x11, 0x00, 0xe8, 0xd3, 0x09,
        0xba, 0xd0, 0x9b, 0x01, 0x00, 0x09, 0x07, 0x09, 0x04, 0x80, 0x40, 0x00,
        0x00, 0x08, 0x0e, 0x09, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x50, 0x6f,
        0x9a, 0x02, 0x0f, 0x09, 0x00, 0x00, 0x09, 0x04, 0x14, 0x15, 0x22, 0x00,
        0x00, 0x08, 0x0b, 0x02, 0x00, 0x55, 0x53, 0x1e, 0x14, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x09, 0x00, 0x00, 0x17, 0xf2,
        0x10, 0x01, 0x10, 0x00, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx2_pkt,
                                         sizeof(subscribe_bf_idx2_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, discovered_peer_nmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx2_pkt,
                                         sizeof(subscribe_bf_idx2_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, kLocalNmi),
              nan_sda_subscribe);

    // 5. Active Subscribe SDF after NMI rotation with Exclude Bloom Filter
    // bf_idx=0 (114 bytes):
    // TA=4e:c3:b0:76:cb:2e, srf_ctrl=0x01, 6-byte Bloom filter
    // [20 00 00 10 02 01] (bits 5, 28, 33, 40).
    const uint8_t subscribe_bf_idx0_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0x4e, 0xc3,
        0xb0, 0x76, 0xcb, 0x2e, 0x50, 0x6f, 0x9a, 0x01, 0x0a, 0x1b, 0xb0, 0xdf,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x11, 0x00, 0xe8, 0xd3, 0x09,
        0xba, 0xd0, 0x9b, 0x01, 0x00, 0x09, 0x07, 0x01, 0x20, 0x00, 0x00, 0x10,
        0x02, 0x01, 0x0e, 0x09, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x50, 0x6f,
        0x9a, 0x02, 0x0f, 0x09, 0x00, 0x00, 0x09, 0x04, 0x14, 0x15, 0x22, 0x00,
        0x00, 0x08, 0x0b, 0x02, 0x00, 0x55, 0x53, 0x1e, 0x14, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x09, 0x00, 0x00, 0x17, 0xf2,
        0x10, 0x01, 0x10, 0x00, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx0_pkt,
                                         sizeof(subscribe_bf_idx0_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, discovered_peer_nmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx0_pkt,
                                         sizeof(subscribe_bf_idx0_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, kLocalNmi),
              nan_sda_subscribe);

    // 6. Follow-up SDF (182 bytes):
    // DA=2a:6d:f5:db:5f:f1, TA=fa:89:0e:af:db:0f, inst_id=1, req_inst_id=1,
    // srv_ctrl=0x02 Follow-up, followed by SDEA 0x0e, Device Capability 0x0f,
    // NAN Availability 0x12, and NPBA 0x2c.
    const uint8_t followup_pkt[] = {
        0xd0, 0x00, 0x30, 0x00, 0x2a, 0x6d, 0xf5, 0xdb, 0x5f, 0xf1, 0xfa, 0x89,
        0x0e, 0xaf, 0xdb, 0x0f, 0x50, 0x6f, 0x9a, 0x01, 0x0a, 0x1b, 0xb0, 0x76,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x09, 0x00, 0xe8, 0xd3, 0x09,
        0xba, 0xd0, 0x9b, 0x01, 0x01, 0x02, 0x0e, 0x46, 0x00, 0x01, 0x00, 0x00,
        0x41, 0x00, 0x50, 0x6f, 0x9a, 0x02, 0x04, 0x3a, 0x00, 0x10, 0x6d, 0x6f,
        0x64, 0x65, 0x6c, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x44, 0x65, 0x76, 0x69,
        0x63, 0x65, 0x15, 0x76, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x4e, 0x61, 0x6d,
        0x65, 0x3d, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x43, 0x6f, 0x2e,
        0x12, 0x70, 0x61, 0x69, 0x72, 0x69, 0x6e, 0x67, 0x4e, 0x61, 0x6d, 0x65,
        0x3d, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x0f, 0x09, 0x00, 0x00, 0x09,
        0x04, 0x14, 0x15, 0x22, 0x00, 0x00, 0x08, 0x12, 0x14, 0x00, 0x02, 0x10,
        0x00, 0x0f, 0x00, 0x01, 0x12, 0x20, 0x00, 0x05, 0xff, 0x00, 0x00, 0x00,
        0xff, 0x11, 0x51, 0x20, 0x00, 0x00, 0x12, 0x15, 0x00, 0x02, 0x11, 0x00,
        0x10, 0x00, 0x01, 0x12, 0x20, 0x00, 0x06, 0xff, 0xff, 0x00, 0x00, 0xff,
        0xff, 0x11, 0x80, 0x20, 0x00, 0x01, 0x2c, 0x05, 0x00, 0x55, 0x01, 0x00,
        0x40, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(followup_pkt,
                                         sizeof(followup_pkt),
                                         33, 9, service_id,
                                         0x00 /* Publisher */, 1, nullptr),
              nan_sda_follow_up);
}

TEST(ApfSdaTest, CapturedSdfFramesWithNonFirstSdaAndAllBloomIndices) {
    // Captured over-the-air 802.11 NAN SDF frames between a publisher
    // (02:02:fc:67:76:a7) and a subscriber (4a:bb:93:6f:20:ac) exercising:
    // - Non-first SDA placement where preceding NAN attributes (0x0f, 0x2a,
    //   0x12, 0x12) place the SDA payload at mid-frame offsets 158 and 146.
    // - Exclude Bloom Filter SRFs across all four hash indices (bf_idx 0..3)
    //   within a single discovery session (Service ID a4:97:75:64:df:aa).
    const uint8_t service_id[6] = {0xa4, 0x97, 0x75, 0x64, 0xdf, 0xaa};
    const uint8_t discovered_publisher_nmi[6] = {0x02, 0x02, 0xfc, 0x67, 0x76, 0xa7};

    // 1. Unsolicited Publish SDF with SDA at offset 158 (260 bytes):
    // Preceded by Device Capability 0x0f (9B), DCEA 0x2a (2B), and two NAN
    // Availability 0x12 attributes (51B + 51B), placing the 9-byte SDA at
    // sda_offset=158, followed by SDEA 0x0e, CSIA 0x22, SCIA 0x23, Country
    // Code 0x0b, NPBA 0x2c, NIRA 0x2b, and Extended WLAN Infrastructure 0x1e.
    const uint8_t publish_sda_offset_158_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0x02, 0x02,
        0xfc, 0x67, 0x76, 0xa7, 0x50, 0x6f, 0x9a, 0x01, 0x09, 0xfd, 0x30, 0x00,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x0f, 0x09, 0x00, 0x00, 0x89, 0x04,
        0x14, 0x15, 0x22, 0x10, 0x2f, 0x08, 0x2a, 0x02, 0x00, 0x05, 0x03, 0x12,
        0x33, 0x00, 0x77, 0x32, 0x00, 0x0e, 0x00, 0x19, 0x12, 0x18, 0x00, 0x04,
        0x03, 0x00, 0x03, 0x00, 0x11, 0x51, 0x20, 0x00, 0x00, 0x0e, 0x00, 0x0a,
        0x12, 0x18, 0x00, 0x04, 0xfc, 0xff, 0xfc, 0x3f, 0x11, 0x51, 0xff, 0x1f,
        0x00, 0x0e, 0x00, 0x0a, 0x12, 0x18, 0x00, 0x04, 0xfc, 0xff, 0xfc, 0xff,
        0x11, 0x51, 0x20, 0x00, 0x00, 0x12, 0x33, 0x00, 0x77, 0x31, 0x00, 0x0e,
        0x00, 0x19, 0x12, 0x18, 0x00, 0x04, 0x00, 0x0f, 0x00, 0x00, 0x11, 0x80,
        0x20, 0x00, 0x01, 0x0e, 0x00, 0x1a, 0x12, 0x18, 0x00, 0x04, 0xff, 0x00,
        0xff, 0x00, 0x11, 0x80, 0x01, 0x00, 0x01, 0x0e, 0x00, 0x0a, 0x12, 0x18,
        0x00, 0x04, 0x00, 0xf0, 0x00, 0xff, 0x11, 0x80, 0x20, 0x00, 0x01, 0x03,
        0x09, 0x00, 0xa4, 0x97, 0x75, 0x64, 0xdf, 0xaa, 0x01, 0x00, 0x00, 0x0e,
        0x03, 0x00, 0x01, 0x40, 0x04, 0x22, 0x05, 0x00, 0x04, 0x05, 0x01, 0x07,
        0x01, 0x23, 0x14, 0x00, 0x10, 0x00, 0x01, 0x01, 0x3f, 0x18, 0xcc, 0xf2,
        0x03, 0xeb, 0xd9, 0xef, 0x97, 0x31, 0x9a, 0x8f, 0x47, 0x74, 0x95, 0xfb,
        0x0b, 0x02, 0x00, 0x55, 0x53, 0x2c, 0x05, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x2b, 0x11, 0x00, 0x00, 0xbe, 0x6d, 0x01, 0x73, 0x89, 0xc8, 0xd2,
        0xb5, 0xff, 0x4f, 0x2c, 0xa8, 0xa2, 0xda, 0xaf, 0xc8, 0x1e, 0x14, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x81, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(publish_sda_offset_158_pkt,
                                         sizeof(publish_sda_offset_158_pkt),
                                         158, 9, service_id,
                                         0x01 /* Subscriber */, 1, nullptr),
              nan_sda_publish);
    EXPECT_EQ(apf_internal_match_nan_sda(publish_sda_offset_158_pkt,
                                         sizeof(publish_sda_offset_158_pkt),
                                         158, 9, service_id,
                                         0x00 /* Publisher */, 0, nullptr),
              nan_sda_ignore);

    // 2. Unsolicited Publish SDF with SDA at offset 146 (248 bytes):
    // Preceded by Device Capability 0x0f (9B), DCEA 0x2a (2B), and two NAN
    // Availability 0x12 attributes (51B + 39B), placing the 9-byte SDA at
    // sda_offset=146.
    const uint8_t publish_sda_offset_146_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0x02, 0x02,
        0xfc, 0x67, 0x76, 0xa7, 0x50, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0xd0, 0x02,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x0f, 0x09, 0x00, 0x00, 0x89, 0x04,
        0x14, 0x15, 0x22, 0x10, 0x2f, 0x08, 0x2a, 0x02, 0x00, 0x05, 0x03, 0x12,
        0x33, 0x00, 0x94, 0x32, 0x00, 0x0e, 0x00, 0x19, 0x12, 0x18, 0x00, 0x04,
        0x03, 0x00, 0x03, 0x00, 0x11, 0x51, 0x20, 0x00, 0x00, 0x0e, 0x00, 0x0a,
        0x12, 0x18, 0x00, 0x04, 0xfc, 0xff, 0xfc, 0x3f, 0x11, 0x51, 0xff, 0x1f,
        0x00, 0x0e, 0x00, 0x0a, 0x12, 0x18, 0x00, 0x04, 0xfc, 0xff, 0xfc, 0xff,
        0x11, 0x51, 0x20, 0x00, 0x00, 0x12, 0x27, 0x00, 0x94, 0x31, 0x00, 0x0e,
        0x00, 0x19, 0x12, 0x18, 0x00, 0x04, 0x00, 0xff, 0x00, 0x00, 0x11, 0x80,
        0x20, 0x00, 0x01, 0x12, 0x00, 0x19, 0x12, 0x20, 0x00, 0x08, 0xff, 0x00,
        0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0x11, 0x80, 0x01, 0x00, 0x01, 0x03,
        0x09, 0x00, 0xa4, 0x97, 0x75, 0x64, 0xdf, 0xaa, 0x01, 0x00, 0x00, 0x0e,
        0x03, 0x00, 0x01, 0x40, 0x04, 0x22, 0x05, 0x00, 0x04, 0x05, 0x01, 0x07,
        0x01, 0x23, 0x14, 0x00, 0x10, 0x00, 0x01, 0x01, 0x3f, 0x18, 0xcc, 0xf2,
        0x03, 0xeb, 0xd9, 0xef, 0x97, 0x31, 0x9a, 0x8f, 0x47, 0x74, 0x95, 0xfb,
        0x0b, 0x02, 0x00, 0x55, 0x53, 0x2c, 0x05, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x2b, 0x11, 0x00, 0x00, 0xc1, 0x26, 0xe6, 0x21, 0x6a, 0x28, 0x10,
        0x03, 0x29, 0xa4, 0x57, 0xba, 0x79, 0x67, 0x0b, 0x51, 0x1e, 0x14, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x81, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(publish_sda_offset_146_pkt,
                                         sizeof(publish_sda_offset_146_pkt),
                                         146, 9, service_id,
                                         0x01 /* Subscriber */, 1, nullptr),
              nan_sda_publish);

    // 3. Active Subscribe SDF with Exclude Bloom Filter bf_idx=0 (226 bytes):
    // srf_ctrl=0x01, 6-byte Bloom filter [44 08 00 80 00 00] (bits 2, 6, 11, 31).
    const uint8_t subscribe_bf_idx0_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0x4a, 0xbb,
        0x93, 0x6f, 0x20, 0xac, 0x50, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0x20, 0x8f,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x11, 0x00, 0xa4, 0x97, 0x75,
        0x64, 0xdf, 0xaa, 0x01, 0x00, 0x09, 0x07, 0x01, 0x44, 0x08, 0x00, 0x80,
        0x00, 0x00, 0x0e, 0x09, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x50, 0x6f,
        0x9a, 0x02, 0x0f, 0x09, 0x00, 0x00, 0x09, 0x04, 0x14, 0x11, 0x22, 0x88,
        0x13, 0x08, 0x12, 0x17, 0x00, 0x10, 0x10, 0x00, 0x12, 0x00, 0x01, 0x12,
        0x20, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x11,
        0x51, 0x20, 0x00, 0x00, 0x12, 0x34, 0x00, 0x10, 0x11, 0x00, 0x12, 0x00,
        0x01, 0x12, 0x20, 0x00, 0x08, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff,
        0xff, 0x11, 0x80, 0x01, 0x00, 0x01, 0x12, 0x00, 0x01, 0x12, 0x20, 0x00,
        0x08, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x11, 0x80, 0x20,
        0x00, 0x01, 0x07, 0x00, 0x1a, 0x02, 0x11, 0x80, 0x01, 0x00, 0x01, 0x13,
        0x0c, 0x00, 0x00, 0x00, 0x42, 0x6f, 0x20, 0xac, 0x00, 0x00, 0x18, 0x00,
        0x01, 0x02, 0x13, 0x0d, 0x00, 0x00, 0x01, 0x44, 0x6f, 0x20, 0xac, 0x00,
        0x01, 0x18, 0x00, 0x02, 0x00, 0x02, 0x0b, 0x02, 0x00, 0x55, 0x53, 0x1e,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x80, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x09,
        0x00, 0x00, 0x17, 0xf2, 0x11, 0x01, 0x10, 0x00, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx0_pkt,
                                         sizeof(subscribe_bf_idx0_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, discovered_publisher_nmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx0_pkt,
                                         sizeof(subscribe_bf_idx0_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, kLocalNmi),
              nan_sda_subscribe);

    // 4. Active Subscribe SDF with Exclude Bloom Filter bf_idx=1 (226 bytes):
    // srf_ctrl=0x05, 6-byte Bloom filter [20 00 00 10 02 01] (bits 5, 28, 33, 40).
    const uint8_t subscribe_bf_idx1_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0x4a, 0xbb,
        0x93, 0x6f, 0x20, 0xac, 0x50, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0xe0, 0x8c,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x11, 0x00, 0xa4, 0x97, 0x75,
        0x64, 0xdf, 0xaa, 0x01, 0x00, 0x09, 0x07, 0x05, 0x20, 0x00, 0x00, 0x10,
        0x02, 0x01, 0x0e, 0x09, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x50, 0x6f,
        0x9a, 0x02, 0x0f, 0x09, 0x00, 0x00, 0x09, 0x04, 0x14, 0x11, 0x22, 0x88,
        0x13, 0x08, 0x12, 0x17, 0x00, 0x10, 0x10, 0x00, 0x12, 0x00, 0x01, 0x12,
        0x20, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x11,
        0x51, 0x20, 0x00, 0x00, 0x12, 0x34, 0x00, 0x10, 0x11, 0x00, 0x12, 0x00,
        0x01, 0x12, 0x20, 0x00, 0x08, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff,
        0xff, 0x11, 0x80, 0x01, 0x00, 0x01, 0x12, 0x00, 0x01, 0x12, 0x20, 0x00,
        0x08, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x11, 0x80, 0x20,
        0x00, 0x01, 0x07, 0x00, 0x1a, 0x02, 0x11, 0x80, 0x01, 0x00, 0x01, 0x13,
        0x0c, 0x00, 0x00, 0x00, 0x42, 0x6f, 0x20, 0xac, 0x00, 0x00, 0x18, 0x00,
        0x01, 0x02, 0x13, 0x0d, 0x00, 0x00, 0x01, 0x44, 0x6f, 0x20, 0xac, 0x00,
        0x01, 0x18, 0x00, 0x02, 0x00, 0x02, 0x0b, 0x02, 0x00, 0x55, 0x53, 0x1e,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x80, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x09,
        0x00, 0x00, 0x17, 0xf2, 0x11, 0x01, 0x10, 0x00, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx1_pkt,
                                         sizeof(subscribe_bf_idx1_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, discovered_publisher_nmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx1_pkt,
                                         sizeof(subscribe_bf_idx1_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, kLocalNmi),
              nan_sda_subscribe);

    // 5. Active Subscribe SDF with Exclude Bloom Filter bf_idx=2 (175 bytes):
    // srf_ctrl=0x09, 6-byte Bloom filter [00 10 20 01 02 00] (bits 12, 21, 24, 33).
    const uint8_t subscribe_bf_idx2_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0x4a, 0xbb,
        0x93, 0x6f, 0x20, 0xac, 0x50, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0xc0, 0x87,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x11, 0x00, 0xa4, 0x97, 0x75,
        0x64, 0xdf, 0xaa, 0x01, 0x00, 0x09, 0x07, 0x09, 0x00, 0x10, 0x20, 0x01,
        0x02, 0x00, 0x0e, 0x09, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x50, 0x6f,
        0x9a, 0x02, 0x0f, 0x09, 0x00, 0x00, 0x09, 0x04, 0x14, 0x11, 0x22, 0x88,
        0x13, 0x08, 0x12, 0x17, 0x00, 0x06, 0x30, 0x00, 0x12, 0x00, 0x01, 0x12,
        0x20, 0x00, 0x08, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x11,
        0x51, 0x20, 0x00, 0x00, 0x12, 0x20, 0x00, 0x06, 0x31, 0x00, 0x12, 0x00,
        0x01, 0x12, 0x20, 0x00, 0x08, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00,
        0x00, 0x11, 0x80, 0x20, 0x00, 0x01, 0x07, 0x00, 0x1a, 0x02, 0x11, 0x80,
        0x01, 0x00, 0x01, 0x0b, 0x02, 0x00, 0x55, 0x53, 0x1e, 0x14, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x80, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x09, 0x00, 0x00, 0x17,
        0xf2, 0x11, 0x01, 0x10, 0x00, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx2_pkt,
                                         sizeof(subscribe_bf_idx2_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, discovered_publisher_nmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx2_pkt,
                                         sizeof(subscribe_bf_idx2_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, kLocalNmi),
              nan_sda_subscribe);

    // 6. Active Subscribe SDF with Exclude Bloom Filter bf_idx=3 (226 bytes):
    // srf_ctrl=0x0d, 6-byte Bloom filter [00 08 04 80 40 00] (bits 11, 18, 31, 38).
    const uint8_t subscribe_bf_idx3_pkt[] = {
        0xd0, 0x00, 0x00, 0x00, 0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0x4a, 0xbb,
        0x93, 0x6f, 0x20, 0xac, 0x50, 0x6f, 0x9a, 0x01, 0x00, 0x00, 0xa0, 0x9a,
        0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13, 0x03, 0x11, 0x00, 0xa4, 0x97, 0x75,
        0x64, 0xdf, 0xaa, 0x01, 0x00, 0x09, 0x07, 0x0d, 0x00, 0x08, 0x04, 0x80,
        0x40, 0x00, 0x0e, 0x09, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x50, 0x6f,
        0x9a, 0x02, 0x0f, 0x09, 0x00, 0x00, 0x09, 0x04, 0x14, 0x11, 0x22, 0x88,
        0x13, 0x08, 0x12, 0x17, 0x00, 0x10, 0x10, 0x00, 0x12, 0x00, 0x01, 0x12,
        0x20, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x11,
        0x51, 0x20, 0x00, 0x00, 0x12, 0x34, 0x00, 0x10, 0x11, 0x00, 0x12, 0x00,
        0x01, 0x12, 0x20, 0x00, 0x08, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0xff,
        0xff, 0x11, 0x80, 0x01, 0x00, 0x01, 0x12, 0x00, 0x01, 0x12, 0x20, 0x00,
        0x08, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x11, 0x80, 0x20,
        0x00, 0x01, 0x07, 0x00, 0x1a, 0x02, 0x11, 0x80, 0x01, 0x00, 0x01, 0x13,
        0x0c, 0x00, 0x00, 0x00, 0x42, 0x6f, 0x20, 0xac, 0x00, 0x00, 0x18, 0x00,
        0x01, 0x02, 0x13, 0x0d, 0x00, 0x00, 0x01, 0x44, 0x6f, 0x20, 0xac, 0x00,
        0x01, 0x18, 0x00, 0x02, 0x00, 0x02, 0x0b, 0x02, 0x00, 0x55, 0x53, 0x1e,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x80, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x09,
        0x00, 0x00, 0x17, 0xf2, 0x11, 0x01, 0x10, 0x00, 0x00, 0x00
    };
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx3_pkt,
                                         sizeof(subscribe_bf_idx3_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, discovered_publisher_nmi),
              nan_sda_ignore);
    EXPECT_EQ(apf_internal_match_nan_sda(subscribe_bf_idx3_pkt,
                                         sizeof(subscribe_bf_idx3_pkt),
                                         33, 17, service_id,
                                         0x0c /* Solicited Publisher + SRF enable */,
                                         1, kLocalNmi),
              nan_sda_subscribe);
}

}  // namespace apf
