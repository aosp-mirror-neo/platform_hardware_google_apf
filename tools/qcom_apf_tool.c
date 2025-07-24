#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#include <linux/ethtool.h>
#include <linux/nl80211.h>
#include <linux/sockios.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#define QCA_NL80211_VENDOR_ID 0x001374

// Using the direct PACKET_FILTER subcommand from poc.c and wifi_hal.cpp
#define QCA_NL80211_VENDOR_SUBCMD_PACKET_FILTER 83

// Nested subcommands for the PACKET_FILTER command
enum packet_filter_sub_cmd {
    QCA_WLAN_SET_PACKET_FILTER = 1,
    QCA_WLAN_GET_PACKET_FILTER = 2,
    QCA_WLAN_WRITE_PACKET_FILTER = 3,
    QCA_WLAN_READ_PACKET_FILTER = 4,
    QCA_WLAN_ENABLE_PACKET_FILTER = 5,
    QCA_WLAN_DISABLE_PACKET_FILTER = 6,
};

// Attributes nested inside the PACKET_FILTER command
enum qca_wlan_vendor_attr_packet_filter {
    QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_INVALID = 0,
    QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_SUB_CMD = 1,
    QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_VERSION = 2,
    QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_ID = 3,
    QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_SIZE = 4,
    QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_CURRENT_OFFSET = 5,
    QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_PROGRAM = 6,
    QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_PROG_LENGTH = 7,
    QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_MAX,
};

// Checks if the driver for the interface is "cnss_pci"
bool check_driver_is_cnss_pci(const char *ifname) {
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
    return !strcmp(drvinfo.driver, "cnss_pci");
}

static int g_apf_ram_size = 0;
struct nl_sock *nl_sk = NULL;
int nl80211_id = 0;
int iface_index = 0;

static int response_handler(struct nl_msg *msg, __unused void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *vendor_tb[QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_MAX + 1] = {0};

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
    if (!tb[NL80211_ATTR_VENDOR_DATA]) return NL_OK;

    if (nla_parse_nested(vendor_tb, QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_MAX, tb[NL80211_ATTR_VENDOR_DATA], NULL)) {
        fprintf(stderr, "Failed to parse vendor data\n");
        return NL_SKIP;
    }

    if (vendor_tb[QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_VERSION] &&
        vendor_tb[QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_SIZE]) {
        uint32_t version = nla_get_u32(vendor_tb[QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_VERSION]);
        g_apf_ram_size = nla_get_u32(vendor_tb[QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_SIZE]);
        printf("APF capabilities, version = %u, max_len = %u bytes\n", version, g_apf_ram_size);
    }

    if (vendor_tb[QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_PROGRAM]) {
        unsigned char *data = (unsigned char *)nla_data(vendor_tb[QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_PROGRAM]);
        int len = nla_len(vendor_tb[QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_PROGRAM]);
        printf("APF Memory Read (%d bytes):\n", len);
        for (int i = 0; i < len; i++) printf("%02x", data[i]);
        printf("\n");
    }

    return NL_OK;
}

void get_apf_capabilities() {
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) return;

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id, 0, 0, NL80211_CMD_VENDOR, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, QCA_NL80211_VENDOR_ID);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, QCA_NL80211_VENDOR_SUBCMD_PACKET_FILTER);

    struct nlattr *vendor_data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_SUB_CMD, QCA_WLAN_GET_PACKET_FILTER);
    nla_nest_end(msg, vendor_data);

    nl_send_auto(nl_sk, msg);
    nl_recvmsgs_default(nl_sk);
    nlmsg_free(msg);
}

void set_apf_state(int enable) {
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) return;

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id, 0, 0, NL80211_CMD_VENDOR, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, QCA_NL80211_VENDOR_ID);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, QCA_NL80211_VENDOR_SUBCMD_PACKET_FILTER);

    struct nlattr *vendor_data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_SUB_CMD,
                enable ? QCA_WLAN_ENABLE_PACKET_FILTER : QCA_WLAN_DISABLE_PACKET_FILTER);
    nla_nest_end(msg, vendor_data);

    nl_send_auto(nl_sk, msg);
    nl_recvmsgs_default(nl_sk);
    nlmsg_free(msg);
}

void load_apf_program(const unsigned char *prog, size_t len) {
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) return;

    set_apf_state(0); // Disable before writing

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id, 0, 0, NL80211_CMD_VENDOR, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, QCA_NL80211_VENDOR_ID);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, QCA_NL80211_VENDOR_SUBCMD_PACKET_FILTER);

    struct nlattr *vendor_data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_SUB_CMD, QCA_WLAN_WRITE_PACKET_FILTER);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_CURRENT_OFFSET, 0);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_PROG_LENGTH, len);
    nla_put(msg, QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_PROGRAM, len, prog);
    nla_nest_end(msg, vendor_data);

    if (nl_send_auto(nl_sk, msg) < 0) {
        fprintf(stderr, "Failed to send 'set' command\n");
    } else {
        printf("APF program loaded.\n");
    }
    nlmsg_free(msg);
    nl_recvmsgs_default(nl_sk);

    set_apf_state(1); // Enable after writing
}

void read_apf_memory(unsigned int offset, unsigned int length) {
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) return;

    set_apf_state(0); // Disable before reading

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id, 0, 0, NL80211_CMD_VENDOR, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface_index);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, QCA_NL80211_VENDOR_ID);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, QCA_NL80211_VENDOR_SUBCMD_PACKET_FILTER);

    struct nlattr *vendor_data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_SUB_CMD, QCA_WLAN_READ_PACKET_FILTER);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_SIZE, length);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_CURRENT_OFFSET, offset);
    nla_nest_end(msg, vendor_data);

    nl_send_auto(nl_sk, msg);
    nl_recvmsgs_default(nl_sk);
    nlmsg_free(msg);

    set_apf_state(1); // Re-enable after reading
}

int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <iface> [get_caps|set <hex_program>|read [offset len]]\n", argv[0]);
        return 1;
    }

    if (!check_driver_is_cnss_pci(argv[1])) {
        fprintf(stderr, "Error: This tool is intended for Qualcomm 'cnss_pci' driver only.\n");
        return 1;
    }

    iface_index = if_nametoindex(argv[1]);
    if (iface_index == 0) {
        perror("if_nametoindex");
        return 1;
    }

    nl_sk = nl_socket_alloc();
    if (!nl_sk) {
        fprintf(stderr, "Failed to allocate netlink socket.\n");
        return 1;
    }
    if (genl_connect(nl_sk)) {
        fprintf(stderr, "Failed to connect to generic netlink.\n");
        nl_socket_free(nl_sk);
        return 1;
    }
    nl80211_id = genl_ctrl_resolve(nl_sk, "nl80211");
    if (nl80211_id < 0) {
        fprintf(stderr, "nl80211 not found.\n");
        nl_socket_free(nl_sk);
        return 1;
    }
    nl_socket_modify_cb(nl_sk, NL_CB_VALID, NL_CB_CUSTOM, response_handler, NULL);

    const char *cmd = argv[2];
    if (strcmp(cmd, "get_caps") == 0) {
        get_apf_capabilities();
    } else if (strcmp(cmd, "set") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s <iface> set <hex_program>\n", argv[0]);
            return 1;
        }
        const char *hex_prog = argv[3];
        size_t hex_len = strlen(hex_prog);
        if (hex_len & 1) {
            fprintf(stderr, "Error: Hex string must have an even number of characters.\n");
            return 1;
        }
        size_t prog_len = hex_len / 2;
        unsigned char *prog_bytes = (unsigned char *)malloc(prog_len);
        for (size_t i = 0; i < prog_len; i++) {
            int high = hex_char_to_int(hex_prog[i * 2]);
            int low = hex_char_to_int(hex_prog[i * 2 + 1]);
            prog_bytes[i] = (high << 4) | low;
        }
        load_apf_program(prog_bytes, prog_len);
        free(prog_bytes);
    } else if (strcmp(cmd, "read") == 0) {
        if (argc == 3) { // Read full memory
            get_apf_capabilities();
            if (g_apf_ram_size > 0) {
                read_apf_memory(0, g_apf_ram_size);
            } else {
                fprintf(stderr, "Could not determine APF RAM size.\n");
            }
        } else if (argc == 5) {
            unsigned int offset = strtoul(argv[3], NULL, 0);
            unsigned int length = strtoul(argv[4], NULL, 0);
            read_apf_memory(offset, length);
        } else {
            fprintf(stderr, "Usage: %s <iface> read [offset len]\n", argv[0]);
            return 1;
        }
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
    }

    nl_socket_free(nl_sk);
    return 0;
}
