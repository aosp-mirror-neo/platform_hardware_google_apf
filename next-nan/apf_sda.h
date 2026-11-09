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

#ifndef APF_SDA_H_
#define APF_SDA_H_

/* Requires <stdbool.h> and <stdint.h> (apf_interpreter.h includes both) and apf_defs.h
 * (u8, u32) to be included first. */

/* CRC-32 implementation selector; see APF_CRC32_IMPL in apf_interpreter.h. */
#ifndef APF_CRC32_TABLE
#define APF_CRC32_TABLE 1
#define APF_CRC32_BITWISE 2
#define APF_CRC32_EXTERNAL 3
#endif
#ifndef APF_CRC32_IMPL
#define APF_CRC32_IMPL APF_CRC32_TABLE
#endif

/**
 * Computes the IEEE 802.11 FCS CRC-32 (generator polynomial
 * G(x) = x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 +
 * x^5 + x^4 + x^2 + x + 1, reflected polynomial 0xEDB88320; port of
 * wpa_supplicant's ieee80211_crc32() in src/utils/crc32.c).
 *
 * Controlled by APF_CRC32_IMPL (see apf_interpreter.h):
 * - APF_CRC32_TABLE (default): 256-entry lookup table (1,024 bytes of .rodata)
 *   for speed.
 * - APF_CRC32_BITWISE: table-less bitwise calculation to save 1,024 bytes of
 *   .rodata on RAM-constrained firmware.
 * - APF_CRC32_EXTERNAL: external firmware hook apf_ieee80211_crc32() (e.g.
 *   hardware-accelerated CRC-32).
 */
#if APF_CRC32_IMPL == APF_CRC32_TABLE

static const u32 apf_crc32_table[256] = {
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

static u32 apf_ieee80211_crc32(const u8* const frame, const u32 frame_len) {
    u32 crc = 0xFFFFFFFFu;
    for (u32 i = 0; i < frame_len; i++) {
        crc = apf_crc32_table[(crc ^ frame[i]) & 0xFFu] ^ (crc >> 8u);
    }
    return ~crc;
}

#elif APF_CRC32_IMPL == APF_CRC32_BITWISE

static u32 apf_ieee80211_crc32(const u8* const frame, const u32 frame_len) {
    u32 crc = 0xFFFFFFFFu;
    for (u32 i = 0; i < frame_len; i++) {
        crc ^= frame[i];
        for (u32 bit = 0; bit < 8u; bit++) {
            /* Branchless step: GCC 15+ (-foptimize-crc) and recent clang (-O1 to
             * -O3) rewrite the branching form into a 1 KB lookup table. */
            crc = (crc >> 1u) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

#elif APF_CRC32_IMPL == APF_CRC32_EXTERNAL

#ifdef __cplusplus
extern "C" {
#endif
uint32_t apf_ieee80211_crc32(const uint8_t *buf, uint32_t len);
#ifdef __cplusplus
}
#endif

#else
#error "APF_CRC32_IMPL must be APF_CRC32_TABLE, APF_CRC32_BITWISE or APF_CRC32_EXTERNAL"
#endif

/**
 * Checks whether a 6-byte NMI MAC address is present in a NAN Service Response
 * Filter (SRF) Bloom filter (Wi-Fi Aware spec section 10.2; port of
 * wpa_supplicant nan_check_bloom_filter()).
 */
static bool apf_nan_check_bloom_filter(const u8* const nmi,
                                       const u8* const bf,
                                       const u32 bf_len,
                                       const u8 bf_idx) {
    if (bf_len == 0u || bf_len > 255u || !nmi || !bf) return false;
    u8 a_j_x[7];
    for (u32 i = 0; i < 6u; i++) {
        a_j_x[1u + i] = nmi[i];
    }
    const u32 filter_bits = bf_len * 8u;
    const u32 start_j = 4u * (u32)bf_idx;
    for (u32 j = start_j; j < start_j + 4u; j++) {
        a_j_x[0] = (u8)j;
        const u32 crc = (~apf_ieee80211_crc32(a_j_x, 7u)) & 0xFFFFu;
        /* On cores without a hardware divider, this modulo needs the compiler
         * runtime's unsigned modulo helper (e.g. __aeabi_uidivmod). */
        const u32 bit = crc % filter_bits;
        if (!(bf[bit / 8u] & (u8)(1u << (bit % 8u)))) {
            return false;
        }
    }
    return true;
}

/**
 * Per-SDA result of apf_internal_match_nan_sda(). Only the caller decides the
 * frame verdict: it walks every SDA, and drops the frame only when no SDA gives
 * a reason to pass (nan_sda_publish, nan_sda_subscribe or nan_sda_follow_up).
 */
typedef enum {
    nan_sda_error_program = -2, /* invalid caller arguments (EXCEPTION) */
    nan_sda_truncated = -1,     /* SDA overruns the packet: stop the walk, keep earlier results */
    nan_sda_ignore = 0,         /* use case 1: no reason to pass the frame; go on to the next SDA */
    nan_sda_publish = 1,        /* use case 2: reason to pass, unless repeat suppression drops it */
    nan_sda_subscribe = 2,      /* use case 3: reason to pass */
    nan_sda_follow_up = 3,      /* use case 4: reason to pass */
} nan_sda_result;

/**
 * Checks one Wi-Fi Aware (NAN) Service Descriptor Attribute (SDA) payload
 * against a local service and the local device role/configuration.
 *
 * Port of wpa_supplicant's nan_de_rx_sda() and nan_srf_match() logic.
 *
 * Per-SDA check of the Wi-Fi Aware RX filter. Use cases covered:
 * - Frames for services we do not have: nan_sda_ignore (message type does not
 *   fit the local role, different Service ID, or a Publish reply addressed to
 *   another subscriber's Requestor Instance ID).
 * - Publish frames for our subscribe: nan_sda_publish.
 * - Subscribe frames for our publish: nan_sda_subscribe when config bit 2 is
 *   set; nan_sda_ignore for an unsolicited-only publish.
 * - Follow-up frames: nan_sda_follow_up whenever the Service ID matches, for
 *   either local role.
 * Common to every use case: SDA bounds, reserved message type, Service ID
 * (skipped when randomized), optional-field bounds and SRF membership. A
 * malformed SDA, or an SRF that excludes local_nmi, gives nan_sda_ignore.
 * Not covered here (the caller's job):
 * - Repeat suppression for Publish frames (passing only the first copy): it
 *   needs a CRC-32 of the whole frame, so it is done separately.
 * - Frame-level steps: the NAN SDF signature check, the A3 Cluster ID rule,
 *   passing frames that carry a Proxy Meta attribute, and walking every SDA
 *   (the frame passes if any SDA gives a reason to pass).
 *
 * Evaluation order:
 * 1. Caller/program argument checks (nan_sda_error_program), then the SDA
 *    bounds against the packet (nan_sda_truncated).
 * 2. Common checks, for every message type (any failure gives nan_sda_ignore):
 *    a. 9-byte SDA header and reserved message type 3.
 *    b. 6-byte Service ID match (SHA-256 hash prefix), skipped when Service ID
 *       randomization (srv_ctrl & 0x80, wpa_supplicant's
 *       NAN_SRV_CTRL_SERVICE_ID_RANDOMIZATION) is set so candidate randomized
 *       frames pass to the host for IRSA/RSIA + SipHash-2-4 resolution.
 *    c. Bounds of the optional Binding Bitmap, Matching Filter and Service
 *       Response Filter (SRF) fields.
 *    d. SRF MAC address list and Bloom filter membership (Include and Exclude
 *       modes) when enabled in config.
 * 3. Use-case checks, by message type (Publish, Subscribe, Follow-up): local
 *    role, Requestor Instance ID and config bit 2.
 * Service Specific Info (SSI) is app payload, never part of matching, and is
 * never read.
 *
 * Note: This helper intentionally does NOT check the following:
 * - Matching Filter contents (the optional Matching Filter field is traversed
 *   and bounds-checked, not compared) and Discovery Range Limited
 *   (srv_ctrl & 0x20) / RSSI threshold. These are left to the host, and the
 *   caller must not filter on them either: wpa_supplicant processes the
 *   Element Container (P2P USD and proximity ranging) before
 *   nan_de_rx_publish() and nan_de_rx_subscribe() check them, and
 *   nan_de_rx_follow_up() checks neither.
 * - A3 Cluster ID matching for synchronized services. The caller may check it
 *   per frame only when every host session is synchronized, and must never
 *   drop a Follow-up SDA on it.
 * - SDAs inside a NAN Proxy Meta attribute (0x33). The host also processes
 *   the SDA carried inside a Proxy Meta attribute, but this helper only
 *   evaluates top-level SDAs, so the caller must pass any frame containing a
 *   Proxy Meta attribute to the host.
 *
 * @param packet          Pointer to the start of the packet buffer.
 * @param packet_len      Total physical length of the packet buffer.
 * @param sda_ofs         Absolute byte offset in packet where the SDA payload starts.
 * @param sda_len         Length of the SDA payload.
 * @param target_srv_id   6-byte expected Service ID.
 * @param config          Configuration bitmask:
 *                        - Bits 0-1: Local Role (0 = Publisher, 1 = Subscriber; 2-3 reserved)
 *                        - Bit 2: Solicited flag (publisher only). Set when the local publish
 *                          answers Subscribe messages (wpa_supplicant's publish.solicited,
 *                          whether or not it is also unsolicited), uses proximity ranging, or
 *                          is a P2P USD service (for the latter two, the host processes the
 *                          Element Container of a received Subscribe before
 *                          nan_de_rx_subscribe() rejects it). Clear it only for an
 *                          unsolicited-only publish that uses neither proximity ranging nor
 *                          P2P USD. Ignored for a Subscriber.
 *                        - Bit 3: SRF Enable (1 = Filter on SRF, 0 = Ignore SRF membership)
 *                        - Bits 4-7: Reserved (must be 0)
 * @param local_inst_id   Local Service Instance ID (1..255 for solicited publish matching,
 *                        or 0 to match any requestor instance ID).
 * @param local_nmi       6-byte Local NAN Management Interface MAC address (must be the device
 *                        NMI de->nmi, not a per-service forced address; or NULL if SRF disabled).
 * @return                The per-SDA result (see nan_sda_result). This helper never decides
 *                        the frame verdict: the caller walks every SDA and drops the frame
 *                        only when no SDA gives a reason to pass.
 *                        - nan_sda_publish, nan_sda_subscribe, nan_sda_follow_up: this SDA
 *                          gives a reason to pass the frame (use cases 2, 3 and 4).
 *                        - nan_sda_ignore: this SDA gives no reason to pass (no matching rule,
 *                          malformed within sda_len, or excluded by the SRF); go on to the
 *                          next SDA.
 *                        - nan_sda_truncated: packet is NULL or the SDA attribute overruns
 *                          packet_len. Stop walking the remaining attributes and keep the
 *                          result of the earlier SDAs (like wpa_supplicant's
 *                          nan_de_get_attr()); unlike the DNS opcode, do not drop the frame.
 *                        - nan_sda_error_program: invalid caller/program arguments.
 */
static nan_sda_result apf_internal_match_nan_sda(const u8* const packet,
                                                 const u32 packet_len,
                                                 const u32 sda_ofs,
                                                 const u32 sda_len,
                                                 const u8* const target_srv_id,
                                                 const u8 config,
                                                 const u8 local_inst_id,
                                                 const u8* const local_nmi) {
    /* Caller/program argument checks */
    if (!target_srv_id) return nan_sda_error_program;
    if (config & 0xF0u) return nan_sda_error_program; /* Reserved config bits must be 0 */

    const u8 local_role = config & 0x03u;
    if (local_role > 1u) return nan_sda_error_program; /* Unknown/reserved local role */

    const bool srf_enable = (config & 0x08u) != 0u;
    if (srf_enable && !local_nmi) return nan_sda_error_program;

    /* Safe bounds checking against packet buffer limits */
    if (!packet) return nan_sda_truncated;
    if (sda_ofs > packet_len || sda_len > packet_len - sda_ofs) return nan_sda_truncated;

    /* ---- Common checks, for every message type ---- */

    /* Header length (per nan_de_rx_sda):
     * Service ID (6) + Inst ID (1) + Req Inst ID (1) + Control (1) = 9 bytes.
     * A malformed SDA gives nan_sda_ignore so that multi-SDA frames continue
     * checking subsequent SDAs.
     */
    if (sda_len < 9u) return nan_sda_ignore;

    const u8* const sda = packet + sda_ofs;
    const u8* const rx_service_id = sda;
    const u8 rx_instance_id = sda[6];
    (void)rx_instance_id; /* Unused in filtering; available for debugging */
    const u8 req_instance_id = sda[7];
    const u8 srv_ctrl = sda[8];
    const u8 msg_type = srv_ctrl & 0x03u;

    /* msg_type: 0 = Publish, 1 = Subscribe, 2 = Follow-up (3 is reserved) */
    if (msg_type > 2u) return nan_sda_ignore;

    /* Service ID
     * When wpa_supplicant sets bit 7 (NAN_SRV_CTRL_SERVICE_ID_RANDOMIZATION),
     * it zeroes out the wire Service ID and resolves the real Service ID via
     * IRSA/RSIA + SipHash-2-4 on the host. Skip only the 6-byte Service ID
     * comparison when bit 7 is set while still enforcing all other checks.
     */
    if (!(srv_ctrl & 0x80u /* NAN_SRV_CTRL_SERVICE_ID_RANDOMIZATION */)) {
        for (u32 i = 0; i < 6u; i++) {
            if (rx_service_id[i] != target_srv_id[i]) return nan_sda_ignore;
        }
    }

    /* Optional field bounds (per nan_de_rx_sda) */
    u32 opt_ofs = 9u;

    /* Binding Bitmap, if present (2 bytes) */
    if (srv_ctrl & 0x40u /* NAN_SRV_CTRL_BINDING_BITMAP */) {
        if (opt_ofs + 2u > sda_len) return nan_sda_ignore;
        opt_ofs += 2u;
    }

    /* Matching Filter (1-byte length + content), if present. Its content is
     * never compared here: matching it (nan_de_filter_match()) is left to the
     * host, because a copy of each rule's filter (up to 255 bytes) would cost
     * APF RAM, and the Service ID check already rejects most SDAs. Only its
     * bounds are checked, to reach the SRF that follows; an overrun makes the
     * SDA malformed, as in nan_de_rx_sda(). */
    if (srv_ctrl & 0x04u /* NAN_SRV_CTRL_MATCHING_FILTER */) {
        if (opt_ofs + 1u > sda_len) return nan_sda_ignore;
        u8 filter_len = sda[opt_ofs++];
        if (opt_ofs + filter_len > sda_len) return nan_sda_ignore;
        opt_ofs += filter_len;
    }

    /* Service Response Filter (SRF), if present: bounds, then membership when
     * enabled in config (port of wpa_supplicant nan_srf_match()). */
    if (srv_ctrl & 0x08u /* NAN_SRV_CTRL_RESP_FILTER */) {
        if (opt_ofs + 1u > sda_len) return nan_sda_ignore;
        u8 srf_len = sda[opt_ofs++];
        if (srf_len < 1u || opt_ofs + srf_len > sda_len) return nan_sda_ignore;

        if (srf_enable) {
            u8 srf_ctrl = sda[opt_ofs];
            u32 content_len = (u32)srf_len - 1u;
            const u8* const srf_content = sda + opt_ofs + 1u;
            /* SRF Control byte (Wi-Fi Aware spec section 9.5.4.1):
             * - Bit 0: SRF Type (0 = MAC Address List, 1 = Bloom Filter)
             * - Bit 1: Include (0 = Exclude mode, 1 = Include mode)
             * - Bits 2-3: Bloom Filter Index (0..3)
             */
            const bool srf_type_bf = (srf_ctrl & 0x01u) != 0u;
            const bool include_mode = (srf_ctrl & 0x02u) != 0u;
            bool addr_found = false;

            if (!srf_type_bf) {
                /* MAC Address List Matching (trailing < 6 bytes ignored per nan_srf_match) */
                u32 num_macs = content_len / 6u;
                for (u32 m = 0; m < num_macs; m++) {
                    bool match_this = true;
                    for (u32 b = 0; b < 6u; b++) {
                        if (srf_content[m * 6u + b] != local_nmi[b]) {
                            match_this = false;
                            break;
                        }
                    }
                    if (match_this) {
                        addr_found = true;
                        break;
                    }
                }
            } else {
                /* Bloom Filter Matching */
                if (content_len == 0u) return nan_sda_ignore; /* Empty Bloom filter is rejected */
                const u8 bf_idx = (u8)((srf_ctrl >> 2u) & 0x03u);
                addr_found = apf_nan_check_bloom_filter(local_nmi, srf_content, content_len, bf_idx);
            }

            /* Exclude mode: ignore the SDA if our MAC is found in the filter.
             * Include mode: ignore the SDA if our MAC is NOT found in the filter.
             */
            if ((include_mode && !addr_found) || (!include_mode && addr_found)) {
                return nan_sda_ignore;
            }
        }
    }

    /* Service Specific Info (SSI), if present, follows. It is app payload, never
     * part of matching, and is never read. */

    /* ---- Use-case checks, by message type ---- */
    const bool is_publisher = (local_role == 0u);
    const bool solicited_flag = (config & 0x04u) != 0u;

    switch (msg_type) {
    case 0u: /* Publish: publish frames for our subscribe */
        /* A publisher does not handle Publish messages (nan_de_rx_sda() skips them). */
        if (is_publisher) return nan_sda_ignore;
        /* Requestor Instance ID: 0 = unsolicited announcement; otherwise a reply to
         * the subscriber with that instance ID, as in nan_de_rx_sda(). Instance ID 0
         * is reserved in NAN, so local_inst_id == 0 matches any requestor. */
        if (req_instance_id != 0u && local_inst_id != 0u && req_instance_id != local_inst_id) {
            return nan_sda_ignore;
        }
        return nan_sda_publish;
    case 1u: /* Subscribe: subscribe frames for our publish */
        /* A subscriber does not handle Subscribe messages (nan_de_rx_sda() skips them). */
        if (!is_publisher) return nan_sda_ignore;
        /* An unsolicited-only publish ignores Subscribe messages, like
         * nan_de_rx_subscribe(): if (!srv->publish.solicited) return false; */
        if (!solicited_flag) return nan_sda_ignore;
        return nan_sda_subscribe;
    default: /* 2 = Follow-up (reserved type 3 was rejected above), for either local role */
        return nan_sda_follow_up;
    }
}

#endif /* APF_SDA_H_ */
