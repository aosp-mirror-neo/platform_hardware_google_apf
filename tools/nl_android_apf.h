/*
 * nl_android_apf.h
 *
 * This header defines the public interface for the nl_android_apf generic
 * netlink family. This interface is intended to be a vendor-agnostic API for
 * configuring the Android Packet Filter (APF) on any network interface that
 * supports it, including wireless and non-wireless interfaces.
 *
 * It provides commands for querying APF capabilities, setting a filter
 * program, and reading the currently installed program.
 */
#ifndef _NL_ANDROID_APF_H_
#define _NL_ANDROID_APF_H_

#include <linux/types.h>

#define NL_ANDROID_APF_FAMILY_NAME "nl_android_apf"
#define NL_ANDROID_APF_VERSION 1

/**
 * enum nl_android_apf_commands - Supported commands
 *
 * @NL_ANDROID_APF_CMD_UNSPEC: Unspecified command.
 * @NL_ANDROID_APF_CMD_GET_CAPABILITIES: Query the device for its APF
 *      capabilities. Requires NL_ANDROID_APF_ATTR_IFINDEX in the request.
 *      Returns attributes for version, max program size, and flags.
 * @NL_ANDROID_APF_CMD_SET_FILTER: Set/install an APF program on the device.
 *      Requires NL_ANDROID_APF_ATTR_IFINDEX and NL_ANDROID_APF_ATTR_PROGRAM.
 * @NL_ANDROID_APF_CMD_GET_FILTER: Retrieve the currently installed APF program
 *      from the device. Requires NL_ANDROID_APF_ATTR_IFINDEX. Returns the
 *      program in NL_ANDROID_APF_ATTR_PROGRAM.
 */
enum nl_android_apf_commands {
    NL_ANDROID_APF_CMD_UNSPEC,
    NL_ANDROID_APF_CMD_GET_CAPABILITIES,
    NL_ANDROID_APF_CMD_SET_FILTER,
    NL_ANDROID_APF_CMD_GET_FILTER,
    __NL_ANDROID_APF_CMD_MAX,
};
#define NL_ANDROID_APF_CMD_MAX (__NL_ANDROID_APF_CMD_MAX - 1)

/**
 * enum nl_android_apf_attributes - Netlink attributes
 *
 * @NL_ANDROID_APF_ATTR_UNSPEC: Unspecified attribute.
 * @NL_ANDROID_APF_ATTR_IFINDEX: (u32) The netdev interface index to operate on.
 * @NL_ANDROID_APF_ATTR_VERSION: (u32) The APF interpreter version supported.
 * @NL_ANDROID_APF_ATTR_MAX_PROGRAM_SIZE: (u32) The maximum size of an APF
 *      program in bytes that the hardware can store.
 * @NL_ANDROID_APF_ATTR_PROGRAM: (binary) The APF bytecode program.
 * @NL_ANDROID_APF_ATTR_PROGRAM_LEN: (u32) The length of the program in bytes.
 *      Used in the GET_FILTER response.
 * @NL_ANDROID_APF_ATTR_FLAGS: (u32) A bitmask of flags. See
 *      NL_ANDROID_APF_FLAG_*.
 */
enum nl_android_apf_attributes {
    NL_ANDROID_APF_ATTR_UNSPEC,
    NL_ANDROID_APF_ATTR_IFINDEX,
    NL_ANDROID_APF_ATTR_VERSION,
    NL_ANDROID_APF_ATTR_MAX_PROGRAM_SIZE,
    NL_ANDROID_APF_ATTR_PROGRAM,
    NL_ANDROID_APF_ATTR_PROGRAM_LEN,
    NL_ANDROID_APF_ATTR_FLAGS,
    __NL_ANDROID_APF_ATTR_MAX,
};
#define NL_ANDROID_APF_ATTR_MAX (__NL_ANDROID_APF_ATTR_MAX - 1)

/**
 * enum nl_android_apf_flags - Feature and status flags
 *
 * @NL_ANDROID_APF_FLAG_FILTER_ENABLED: Indicates if the APF filter is
 *      currently active and processing packets. Returned by GET_CAPABILITIES.
 * @NL_ANDROID_APF_FLAG_ALLOW_DUPLICATE_SET: A flag for SET_FILTER to indicate
 *      that setting the same program again should be allowed. The default
 *      behavior should be to reject a program that is already installed.
 */
enum nl_android_apf_flags {
    NL_ANDROID_APF_FLAG_FILTER_ENABLED      = 1 << 0,
    NL_ANDROID_APF_FLAG_ALLOW_DUPLICATE_SET = 1 << 1,
};

#endif /* _NL_ANDROID_APF_H_ */
