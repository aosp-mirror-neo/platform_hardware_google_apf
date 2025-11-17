/*
 * Copyright 2016, The Android Open Source Project
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

// Simple program to try running an APF program against a packet.

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apflib.h"
#include "disassembler.h"
#include "next/test_buf_allocator.h"

#define __unused __attribute__((unused))

// The following of counter names must be maintained in sync with their Java equivalents in
// https://source.corp.google.com/h/googleplex-android/platform/superproject/main/+/main:packages/modules/NetworkStack/src/android/net/apf/ApfCounterTracker.java
static const char* counter_name [] = {
    "RESERVED_OOB",  // Points to offset 0 from the end of the buffer (out-of-bounds)
    "ENDIANNESS",              // APFv6 interpreter stores 0x12345678 here
    "TOTAL_PACKETS",           // hardcoded in APFv6 interpreter
    "PASSED_ALLOCATE_FAILURE", // hardcoded in APFv6 interpreter
    "PASSED_TRANSMIT_FAILURE", // hardcoded in APFv6 interpreter
    "CORRUPT_DNS_PACKET",      // hardcoded in APFv6 interpreter
    "EXCEPTIONS",              // hardcoded in APFv6.1 interpreter
    "FILTER_AGE_SECONDS",
    "FILTER_AGE_16384THS",
    "APF_VERSION",
    "APF_PROGRAM_ID",
    // The following counters should be maintained in order matching ApfCounterTracker.java.
    "DROPPED_802_3_FRAME",
    "DROPPED_ARP_NON_IPV4",
    "DROPPED_ARP_OTHER_HOST",
    "DROPPED_ARP_REPLY_SPA_NO_HOST",
    "DROPPED_ARP_REQUEST_REPLIED",
    "DROPPED_ARP_UNKNOWN",
    "DROPPED_ARP_V6_ONLY",
    "DROPPED_ETH_BROADCAST",
    "DROPPED_ETHER_OUR_SRC_MAC",
    "DROPPED_ETHERTYPE_NOT_ALLOWED",
    "DROPPED_GARP_REPLY",
    "DROPPED_IGMP_INVALID",
    "DROPPED_IGMP_REPORT",
    "DROPPED_IGMP_V2_GENERAL_QUERY_REPLIED",
    "DROPPED_IGMP_V3_GENERAL_QUERY_REPLIED",
    "DROPPED_IPV4_BROADCAST_ADDR",
    "DROPPED_IPV4_BROADCAST_NET",
    "DROPPED_IPV4_ICMP_INVALID",
    "DROPPED_IPV4_KEEPALIVE_ACK",
    "DROPPED_IPV4_L2_BROADCAST",
    "DROPPED_IPV4_MULTICAST",
    "DROPPED_IPV4_NATT_KEEPALIVE",
    "DROPPED_IPV4_NON_DHCP4",
    "DROPPED_IPV4_PING_REQUEST_REPLIED",
    "DROPPED_IPV4_TCP_PORT7_UNICAST",
    "DROPPED_IPV6_ICMP6_ECHO_REQUEST_INVALID",
    "DROPPED_IPV6_ICMP6_ECHO_REQUEST_REPLIED",
    "DROPPED_IPV6_MLD_INVALID",
    "DROPPED_IPV6_MLD_REPORT",
    "DROPPED_IPV6_MLD_V1_GENERAL_QUERY_REPLIED",
    "DROPPED_IPV6_MLD_V2_GENERAL_QUERY_REPLIED",
    "DROPPED_IPV6_MULTICAST_NA",
    "DROPPED_IPV6_NON_ICMP_MULTICAST",
    "DROPPED_IPV6_NS_INVALID",
    "DROPPED_IPV6_NS_OTHER_HOST",
    "DROPPED_IPV6_NS_REPLIED_NON_DAD",
    "DROPPED_IPV6_ROUTER_SOLICITATION",
    "DROPPED_LOW_POWER_STANDBY",
    "DROPPED_MDNS",
    "DROPPED_MDNS_REPLIED",
    "DROPPED_NON_UNICAST_TDLS",
    "DROPPED_RA",
    "PASSED_ARP_BROADCAST_REPLY",
    "PASSED_ARP_REQUEST",
    "PASSED_ARP_UNICAST_REPLY",
    "PASSED_DHCP",
    "PASSED_DUE_TO_REPLY_OVER_MTU",
    "PASSED_ETHER_OUR_SRC_MAC",
    "PASSED_IPV4",
    "PASSED_IPV4_FROM_DHCPV4_SERVER",
    "PASSED_IPV4_UNICAST",
    "PASSED_IPV6_HOPOPTS",
    "PASSED_IPV6_ICMP",
    "PASSED_IPV6_NON_ICMP",
    "PASSED_IPV6_UNICAST_NON_ICMP",
    "PASSED_LOW_POWER_STANDBY_MAGIC_PACKET",
    "PASSED_LOW_POWER_STANDBY_PORT_ALLOWED",
    "PASSED_MDNS",
    "PASSED_NON_IP_UNICAST",
    "PASSED_RA"
};

enum {
    OPT_PROGRAM,
    OPT_PACKET,
    OPT_PCAP,
    OPT_DATA,
    OPT_AGE,
    OPT_TRACE,
    OPT_VERSION,
};

const struct option long_options[] = {{"program", 1, NULL, OPT_PROGRAM},
                                      {"packet", 1, NULL, OPT_PACKET},
                                      {"pcap", 1, NULL, OPT_PCAP},
                                      {"data", 1, NULL, OPT_DATA},
                                      {"age", 1, NULL, OPT_AGE},
                                      {"trace", 0, NULL, OPT_TRACE},
                                      {"version", 1, NULL, OPT_VERSION},
                                      {"help", 0, NULL, 'h'},
                                      {"cnt", 0, NULL, 'c'},
                                      {NULL, 0, NULL, 0}};

const int COUNTER_SIZE = 4;

// Parses hex in "input". Allocates and fills "*output" with parsed bytes.
// Returns length in bytes of "*output".
size_t parse_hex(const char* input, uint8_t** output) {
    int length = strlen(input);
    if (length & 1) {
        fprintf(stderr, "Argument not even number of characters: %s\n", input);
        exit(1);
    }
    length >>= 1;
    *output = malloc(length);
    if (*output == NULL) {
        fprintf(stderr, "Out of memory, tried to allocate %d\n", length);
        exit(1);
    }
    for (int i = 0; i < length; i++) {
        char byte[3] = { input[i*2], input[i*2+1], 0 };
        char* end_ptr;
        (*output)[i] = strtol(byte, &end_ptr, 16);
        if (end_ptr != byte + 2) {
            fprintf(stderr, "Failed to parse hex %s\n", byte);
            exit(1);
        }
    }
    return length;
}

void print_hex(const uint8_t* input, int len) {
    for (int i = 0; i < len; ++i) {
        printf("%02x", input[i]);
    }
}

uint32_t get_counter_value(uint32_t apf_version, const uint8_t* data, int data_len,
                           int neg_offset) {
    if (neg_offset > -COUNTER_SIZE || neg_offset + data_len < 0) {
        return 0;
    }
    int big_endian = 1;
    if (apf_version >= 6000 && data[data_len - 4] == 0x78 && data[data_len - 1] == 0x12) {
        big_endian = 0;
    }
    uint32_t value = 0;
    if (big_endian) {
        for (int i = 0; i <= 3; ++i) {
            value = value << 8 | data[data_len + neg_offset + i];
        }
    } else {
        for (int i = 3; i >= 0; --i) {
            value = value << 8 | data[data_len + neg_offset + i];
        }
    }
    return value;
}

void print_counter(uint32_t apf_version, const uint8_t* data, int data_len) {
    int counter_len = sizeof(counter_name) / sizeof(counter_name[0]);
    for (int i = 0; i < counter_len; ++i) {
        uint32_t value = get_counter_value(apf_version, data, data_len, -COUNTER_SIZE * i);
        if (value != 0) {
            printf("[%d] %s : %d\n", i, counter_name[i], value);
        }
    }
}

static int tracing_enabled = 0;

void maybe_print_tracing_header() {
    if (!tracing_enabled) return;

    printf("      R0       R1       (size)    PC  Instruction\n");
    printf("-------------------------------------------------\n");

}

void print_all_transmitted_packets() {
    printf("Transmitted packet:\n");
    packet_buffer* current = head;
    while (current) {
        printf("\t");
        print_hex(current->data, (int) current->len);
        printf("\n");
        current = current->next;
    }
}

// Process packet through APF filter
void packet_handler(uint32_t apf_version, uint8_t* program, uint32_t program_len, uint32_t ram_len,
                    const char* pkt, uint32_t filter_age_16384ths) {
    uint8_t* packet;
    uint32_t packet_len = parse_hex(pkt, &packet);

    maybe_print_tracing_header();

    int result = apf_run_generic(apf_version, (uint32_t*)program, program_len, ram_len, packet,
                                 packet_len, filter_age_16384ths);
    printf("Packet %sed\n", result ? "pass" : "dropp");

    free(packet);
}

static int disassemble_as_v6_plus;

void apf_trace_hook(uint32_t pc, const uint32_t* regs, const uint8_t* program, uint32_t program_len,
                    const uint8_t* packet __unused, uint32_t packet_len __unused,
                    const uint32_t* memory __unused, uint32_t memory_len __unused) {
    if (!tracing_enabled) return;

    printf("%8" PRIx32 " %8" PRIx32 "       ", regs[0], regs[1]);
    const disas_ret ret = apf_disassemble(program, program_len, &pc, disassemble_as_v6_plus);
    printf("%s%s\n", ret.prefix, ret.content);
}

// Process pcap file through APF filter and generate output files
void file_handler(uint32_t apf_version, uint8_t* program, uint32_t program_len, uint32_t ram_len,
                  const char* filename, uint32_t filter_age_16384ths) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    struct pcap_pkthdr apf_header;
    const uint8_t* apf_packet;
    pcap_dumper_t *passed_dumper, *dropped_dumper;
    const char passed_file[] = "passed.pcap";
    const char dropped_file[] = "dropped.pcap";
    int pass = 0;
    int drop = 0;

    pcap = pcap_open_offline(filename, errbuf);
    if (pcap == NULL) {
        printf("Open pcap file failed.\n");
        exit(1);
    }

    passed_dumper = pcap_dump_open(pcap, passed_file);
    dropped_dumper = pcap_dump_open(pcap, dropped_file);

    if (!passed_dumper || !dropped_dumper) {
        printf("pcap_dump_open(): open output file failed.\n");
        pcap_close(pcap);
        exit(1);
    }

    while ((apf_packet = pcap_next(pcap, &apf_header)) != NULL) {
        maybe_print_tracing_header();

        int result = apf_run_generic(apf_version, (uint32_t*)program, program_len, ram_len,
                                     apf_packet, apf_header.len, filter_age_16384ths);

        if (!result){
            drop++;
            pcap_dump((u_char*)dropped_dumper, &apf_header, apf_packet);
        } else {
            pass++;
            pcap_dump((u_char*)passed_dumper, &apf_header, apf_packet);
        }
    }

    printf("%d packets dropped\n", drop);
    printf("%d packets passed\n", pass);
    pcap_dump_close(passed_dumper);
    pcap_dump_close(dropped_dumper);
    pcap_close(pcap);
}

void print_usage(char* cmd) {
    fprintf(stderr,
            "Usage: %s --program <program> --pcap <file>|--packet <packet> "
            "[--data <content>] [--age <number>] [--trace] [--version <version>]\n"
            "  --program    APF program, in hex.\n"
            "  --pcap       Pcap file to run through program.\n"
            "  --packet     Packet to run through program.\n"
            "  --data       Data memory contents, in hex.\n"
            "  --age        Age of program in seconds (default: 0).\n"
            "  --trace      Enable APF interpreter debug tracing.\n"
            "  --version    ",
            basename(cmd));
    const uint32_t* versions = apf_supported_versions();
    if (*versions == 0) {
        printf("\nINTERNAL ERROR\n");
        exit(1);
    }
    while (*versions != 0) {
        const uint32_t version = *versions++;
        fprintf(stderr, "%" PRIu32 "%s", version,
                *versions ? "|" :
                        " (default).\n"
                        "  -c, --cnt    Print the APF counters.\n"
                        "  -h, --help   Show this message.\n");
    }
}

int main(int argc, char* argv[]) {
    uint8_t* program = NULL;
    uint32_t program_len;
    const char* filename = NULL;
    char* packet = NULL;
    uint8_t* data = NULL;
    uint32_t data_len = 0;
    double filter_age_seconds = 0.0;
    uint32_t filter_age_16384ths = 0;
    uint32_t apf_version = 0;
    int print_counter_enabled = 0;

    int opt;
    char *endptr;

    while ((opt = getopt_long_only(argc, argv, "ch", long_options, NULL)) != -1) {
        switch (opt) {
            case OPT_PROGRAM:
                program_len = parse_hex(optarg, &program);
                break;
            case OPT_PACKET:
                if (!program) {
                    printf("<packet> requires <program> first\n\'%s -h or --help\' "
                           "for more information\n", basename(argv[0]));
                    exit(1);
                }
                if (filename) {
                    printf("Cannot use <file> with <packet>\n\'%s -h or --help\' "
                           "for more information\n", basename(argv[0]));

                    exit(1);
                }
                packet = optarg;
                break;
            case OPT_PCAP:
                if (!program) {
                    printf("<file> requires <program> first\n\'%s -h or --help\' "
                           "for more information\n", basename(argv[0]));

                    exit(1);
                }
                if (packet) {
                    printf("Cannot use <packet> with <file>\n\'%s -h or --help\' "
                           "for more information\n", basename(argv[0]));

                    exit(1);
                }
                filename = optarg;
                break;
            case OPT_DATA:
                data_len = parse_hex(optarg, &data);
                break;
            case OPT_AGE:
                errno = 0;
                filter_age_seconds = 0.0;
                filter_age_seconds = strtod(optarg, NULL);
                if (errno != 0 || filter_age_seconds <= 0.0) {
                    perror("Filter age must be a positive number.\n");
                    exit(1);
                }
                break;
            case OPT_TRACE:
                tracing_enabled = 1;
                break;
            case OPT_VERSION:
                errno = 0;
                apf_version = strtoul(optarg, &endptr, 10);
                if ((errno == ERANGE && apf_version == UINT32_MAX) ||
                    (errno != 0 && apf_version == 0)) {
                    perror("Error on version option: strtoul");
                    exit(1);
                }
                if (endptr == optarg) {
                    printf("No digit found in version.\n");
                    exit(1);
                }
                if (apf_version == 0) {
                    printf("Version must be non-zero.\n");
                    exit(1);
                }
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
                break;
            case 'c':
                print_counter_enabled = 1;
                break;
            default:
                print_usage(argv[0]);
                exit(1);
                break;
        }
    }

    if (apf_version == 0) {
        // Default to highest supported version.
        const uint32_t* versions = apf_supported_versions();
        while (*versions != 0) {
            apf_version = *versions;
            ++versions;
        }
    }
    disassemble_as_v6_plus = apf_version >= 6000;

    if (!program) {
        printf("Must have APF program in option.\n");
        exit(1);
    }

    if (!filename && !packet) {
        printf("Missing file or packet after program.\n");
        exit(1);
    }

    if ((filter_age_seconds * 16384.0) > UINT32_MAX) {
        printf("Filter age must not be exceptionally large.\n");
        exit(1);
    }
    filter_age_16384ths = (uint32_t)(filter_age_seconds * 16384.0);

    // Combine the program and data into the unified APF buffer.
    uint32_t ram_len = program_len + data_len;
    if (apf_version >= 6000) {
        // Interpreter has hardcoded counters: 5 in v6, 6 in v6.1.
        uint32_t min_data_len = ((apf_version >= 6100) ? 6 : 5) * sizeof(uint32_t);
        if (data_len < min_data_len) {
            ram_len += min_data_len - data_len;
        }
        ram_len += 3;
        ram_len &= ~3;
    }

    if (data) {
        program = realloc(program, ram_len);
        memcpy(program + ram_len - data_len, data, data_len);
        free(data);
    }

    if (filename)
        file_handler(apf_version, program, program_len, ram_len, filename, filter_age_16384ths);
    else
        packet_handler(apf_version, program, program_len, ram_len, packet, filter_age_16384ths);

    if (data_len) {
        printf("Data: ");
        print_hex(program + ram_len - data_len, data_len);
        printf("\n");
        if (print_counter_enabled) {
            printf("APF packet counters:");
            if (apf_version <= 2) {
                printf(" not supported in this version\n");
            } else {
                printf("\n");
                print_counter(apf_version, program + ram_len - data_len, data_len);
            }
        }
    }

    if (apf_version >= 6000 && head != NULL) {
        print_all_transmitted_packets();
    }

    free(program);
    return 0;
}
