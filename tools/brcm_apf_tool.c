#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <linux/nl80211.h>

// ----- CONSTANTS FROM DRIVER SOURCE & STRACE ANALYSIS -----

#define OUI_GOOGLE 0x001A11

// Vendor subcommands
enum {
    APF_SUBCMD_GET_CAPABILITIES = 0x1800,
    APF_SUBCMD_SET_FILTER       = 0x1801,
    APF_SUBCMD_READ_FILTER_DATA = 0x1802,
};

// Nested attributes within VENDOR_DATA
enum {
    APF_ATTRIBUTE_VERSION       = 0,
    APF_ATTRIBUTE_MAX_LEN       = 1,
    APF_ATTRIBUTE_PROGRAM       = 2,
    APF_ATTRIBUTE_PROGRAM_LEN   = 3,
};

// ----- HELPER FUNCTIONS -----

// Checks if the driver for the interface is "wl"
bool check_driver_is_wl(const char *ifname) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("check_driver: socket");
        return false;
    }

    struct ethtool_drvinfo drvinfo = {
        .cmd = ETHTOOL_GDRVINFO,
    };

    struct ifreq ifr = {
        .ifr_data = (caddr_t)&drvinfo,
    };
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
        // This can fail on some virtual interfaces, which is okay.
        perror("check_driver: ioctl(SIOCETHTOOL) failed");
        close(fd);
        return false;
    }

    close(fd);

    printf("Info: Driver for '%s' is '%s'.\n", ifname, drvinfo.driver);
    return !strcmp(drvinfo.driver, "wl");
}

// Converts a hex string like "010407" to a byte array
int hex_str_to_bytes(const char *hex_str, unsigned char *byte_array, size_t max_len) {
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

static int parse_caps_reply(struct nl_msg *msg, __unused void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_VENDOR_DATA]) {
        struct nlattr *caps_tb[APF_ATTRIBUTE_MAX_LEN + 1];
        nla_parse_nested(caps_tb, APF_ATTRIBUTE_MAX_LEN, tb[NL80211_ATTR_VENDOR_DATA], NULL);

        printf("APF Capabilities:\n");
        if (caps_tb[APF_ATTRIBUTE_VERSION])
            printf("  Version: %u\n", nla_get_u32(caps_tb[APF_ATTRIBUTE_VERSION]));
        if (caps_tb[APF_ATTRIBUTE_MAX_LEN])
            printf("  Max Program Size: %u bytes\n", nla_get_u32(caps_tb[APF_ATTRIBUTE_MAX_LEN]));
    }
    return NL_OK;
}

static int parse_read_data_reply(struct nl_msg *msg, __unused void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_VENDOR_DATA]) {
        struct nlattr *prog_tb[APF_ATTRIBUTE_PROGRAM_LEN + 2];
        nla_parse_nested(prog_tb, APF_ATTRIBUTE_PROGRAM_LEN + 1, tb[NL80211_ATTR_VENDOR_DATA], NULL);

        printf("Stored APF Program:\n");
        if (prog_tb[APF_ATTRIBUTE_PROGRAM_LEN])
            printf("  Program Length: %u bytes\n", nla_get_u32(prog_tb[APF_ATTRIBUTE_PROGRAM_LEN]));

        if (prog_tb[APF_ATTRIBUTE_PROGRAM]) {
            unsigned char *data = nla_data(prog_tb[APF_ATTRIBUTE_PROGRAM]);
            int len = nla_len(prog_tb[APF_ATTRIBUTE_PROGRAM]);
            printf("  Program Data: ");
            for (int i=0; i < len; i++) {
                printf("%02x", data[i]);
            }
            printf("\n");
        }
    }
    return NL_OK;
}

static void print_usage(const char *name) {
    fprintf(stderr, "Usage: %s <iface> [get_caps|set <hex_program>|read]\n", name);
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s wlan0 get_caps\n", name);
    fprintf(stderr, "  %s wlan0 set 010407\n", name);
    fprintf(stderr, "  %s wlan0 read\n", name);
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

    // Check that this is a Broadcom wl device before continuing
    if (!check_driver_is_wl(if_name)) {
        fprintf(stderr, "Error: This tool is intended for Broadcom 'wl' driver only. Aborting.\n");
        return 1;
    }

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

    int family_id = genl_ctrl_resolve(sock, "nl80211");
    if (family_id < 0) {
        fprintf(stderr, "Failed to resolve nl80211 family.\n");
        ret = -1; goto cleanup_sock;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM; goto cleanup_sock;
    }

    // Dispatch to the correct command handler
    if (strcmp(command, "get_caps") == 0) {
        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, 0, NL80211_CMD_VENDOR, 0);
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
        nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_GOOGLE);
        nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, APF_SUBCMD_GET_CAPABILITIES);

        nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, parse_caps_reply, NULL);
        ret = nl_send_auto(sock, msg);
        nl_recvmsgs_default(sock);

    } else if (strcmp(command, "set") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: 'set' command requires a hex program string.\n");
            print_usage(argv[0]);
            ret = -1; goto cleanup_msg;
        }
        const char *prog_str = argv[3];
        unsigned char prog_bytes[4096]; // Max APF program size
        int prog_len = hex_str_to_bytes(prog_str, prog_bytes, sizeof(prog_bytes));
        if (prog_len < 0) {
            fprintf(stderr, "Error: Invalid hex program string.\n");
            ret = -1; goto cleanup_msg;
        }

        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST|NLM_F_ACK, NL80211_CMD_VENDOR, 0);
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
        nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_GOOGLE);
        nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, APF_SUBCMD_SET_FILTER);

        struct nlattr *vendor_data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
        if (!vendor_data) { ret = -ENOMEM; goto cleanup_msg; }
        nla_put_u32(msg, APF_ATTRIBUTE_PROGRAM_LEN, prog_len);
        nla_put(msg, APF_ATTRIBUTE_PROGRAM, prog_len, prog_bytes);
        nla_nest_end(msg, vendor_data);

        // nl_send_auto_complete handles the ACK/NACK reply from the kernel
        ret = nl_send_auto_complete(sock, msg);
        if (ret < 0) {
            fprintf(stderr, "Failed to set program, error: %s\n", nl_geterror(ret));
        } else {
            printf("Successfully set APF program (%d bytes).\n", prog_len);
        }

    } else if (strcmp(command, "read") == 0) {
        genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, 0, NL80211_CMD_VENDOR, 0);
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
        nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_GOOGLE);
        nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, APF_SUBCMD_READ_FILTER_DATA);

        nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, parse_read_data_reply, NULL);
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
