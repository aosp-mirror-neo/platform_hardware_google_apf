/*
 * apf_tool.c
 *
 * A vendor-agnostic command-line tool for interacting with the nl_android_apf
 * generic netlink interface. This tool can be used to query APF capabilities
 * and load/read APF programs on any compliant network device.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <net/if.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "nl_android_apf.h"

// ----- HELPER FUNCTIONS -----

// Converts a hex string like "010407" to a byte array
static int hex_str_to_bytes(const char *hex_str, unsigned char *byte_array, size_t max_len) {
    size_t len = strlen(hex_str);
    if (len & 1) return -1; // Must be even length

    size_t byte_count = 0;
    for (size_t i = 0; i < len; i += 2) {
        if (byte_count >= max_len) return -1; // Buffer too small
        if (!isxdigit(hex_str[i]) || !isxdigit(hex_str[i+1])) return -1;

        sscanf(&hex_str[i], "%2hhx", &byte_array[byte_count]);
        byte_count++;
    }
    return byte_count;
}

// ----- NETLINK CALLBACKS FOR PARSING REPLIES -----

static int parse_get_caps_reply(struct nl_msg *msg, __unused void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL_ANDROID_APF_ATTR_MAX + 1];

    nla_parse(tb, NL_ANDROID_APF_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    printf("APF Capabilities:\n");
    if (tb[NL_ANDROID_APF_ATTR_VERSION])
        printf("  Version: %u\n", nla_get_u32(tb[NL_ANDROID_APF_ATTR_VERSION]));
    if (tb[NL_ANDROID_APF_ATTR_MAX_PROGRAM_SIZE])
        printf("  Max Program Size: %u bytes\n", nla_get_u32(tb[NL_ANDROID_APF_ATTR_MAX_PROGRAM_SIZE]));
    if (tb[NL_ANDROID_APF_ATTR_FLAGS]) {
        uint32_t flags = nla_get_u32(tb[NL_ANDROID_APF_ATTR_FLAGS]);
        printf("  Filter Enabled: %s\n", (flags & NL_ANDROID_APF_FLAG_FILTER_ENABLED) ? "yes" : "no");
    }
    return NL_OK;
}

static int parse_get_filter_reply(struct nl_msg *msg, __unused void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL_ANDROID_APF_ATTR_MAX + 1];

    nla_parse(tb, NL_ANDROID_APF_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    printf("Stored APF Program:\n");
    if (tb[NL_ANDROID_APF_ATTR_PROGRAM_LEN])
        printf("  Program Length: %u bytes\n", nla_get_u32(tb[NL_ANDROID_APF_ATTR_PROGRAM_LEN]));

    if (tb[NL_ANDROID_APF_ATTR_PROGRAM]) {
        unsigned char *data = nla_data(tb[NL_ANDROID_APF_ATTR_PROGRAM]);
        int len = nla_len(tb[NL_ANDROID_APF_ATTR_PROGRAM]);
        printf("  Program Data: ");
        for (int i=0; i < len; i++) {
            printf("%02x", data[i]);
        }
        printf("\n");
    }
    return NL_OK;
}

static void print_usage(const char *name) {
    fprintf(stderr, "Usage: %s <iface> [get_caps|set <hex_program>|get]\n", name);
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s wlan0 get_caps\n", name);
    fprintf(stderr, "  %s eth0 set 010407\n", name);
    fprintf(stderr, "  %s wlan0 get\n", name);
}

// ----- MAIN -----

int main(int argc, char **argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *if_name = argv[1];
    const char *command = argv[2];
    int ret = 0;

    int if_index = if_nametoindex(if_name);
    if (if_index == 0) {
        perror("if_nametoindex");
        return 1;
    }

    struct nl_sock *sock = nl_socket_alloc();
    if (!sock) return -ENOMEM;

    if (genl_connect(sock) < 0) {
        fprintf(stderr, "Failed to connect to generic netlink.\n");
        ret = -1; goto cleanup_sock;
    }

    int family_id = genl_ctrl_resolve(sock, NL_ANDROID_APF_FAMILY_NAME);
    if (family_id < 0) {
        fprintf(stderr, "Failed to resolve %s family. Is the kernel module loaded?\n", NL_ANDROID_APF_FAMILY_NAME);
        ret = -1; goto cleanup_sock;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM; goto cleanup_sock;
    }

    if (strcmp(command, "get_caps") == 0) {
        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, 0, NL_ANDROID_APF_CMD_GET_CAPABILITIES, NL_ANDROID_APF_VERSION);
        nla_put_u32(msg, NL_ANDROID_APF_ATTR_IFINDEX, if_index);

        nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, parse_get_caps_reply, NULL);
        ret = nl_send_auto(sock, msg);
        nl_recvmsgs_default(sock);

    } else if (strcmp(command, "set") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: 'set' command requires a hex program string.\n");
            print_usage(argv[0]);
            ret = -1; goto cleanup_msg;
        }
        const char *prog_str = argv[3];
        unsigned char prog_bytes[4096]; // A reasonable max size
        int prog_len = hex_str_to_bytes(prog_str, prog_bytes, sizeof(prog_bytes));
        if (prog_len < 0) {
            fprintf(stderr, "Error: Invalid hex program string.\n");
            ret = -1; goto cleanup_msg;
        }

        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST|NLM_F_ACK, NL_ANDROID_APF_CMD_SET_FILTER, NL_ANDROID_APF_VERSION);
        nla_put_u32(msg, NL_ANDROID_APF_ATTR_IFINDEX, if_index);
        nla_put(msg, NL_ANDROID_APF_ATTR_PROGRAM, prog_len, prog_bytes);

        ret = nl_send_auto_complete(sock, msg);
        if (ret < 0) {
            fprintf(stderr, "Failed to set program, error: %s\n", nl_geterror(ret));
        } else {
            printf("Successfully set APF program (%d bytes).\n", prog_len);
        }

    } else if (strcmp(command, "get") == 0) {
        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, 0, NL_ANDROID_APF_CMD_GET_FILTER, NL_ANDROID_APF_VERSION);
        nla_put_u32(msg, NL_ANDROID_APF_ATTR_IFINDEX, if_index);

        nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, parse_get_filter_reply, NULL);
        ret = nl_send_auto(sock, msg);
        nl_recvmsgs_default(sock);

    } else {
        fprintf(stderr, "Error: Unknown command '%s'\n", command);
        print_usage(argv[0]);
        ret = -1;
    }

cleanup_msg:
    nlmsg_free(msg);
cleanup_sock:
    nl_socket_free(sock);
    return ret < 0 ? 1 : 0;
}