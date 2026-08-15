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

#ifndef APF_INTERPRETER_H_
#define APF_INTERPRETER_H_

#ifdef __KERNEL__
  #include <linux/types.h>
#else
  #include <stdbool.h>
  #include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/****************************
 * APF API Calling Sequence *
 ****************************/

/* User         Kernel              Driver           Firmware
 * space      (apf core)           (netdev)
 * |              |                   |                  |
 * |-- Netlink -->|                   |                  |
 * |              |-ndo_apf_get_info->|                  |
 * |              |                   |------ RPC ------>|
 * |              |                   |                  |-- apf_get_info()
 * |              |                   |                  |       |
 * |              |                   |<-- apf_info -----| <-----'
 * |              |<--- apf_info -----|                  |
 * |<- apf_info --|                   |                  |
 * |              |                   |                  |
 * | (Optional)   |                   |                  |
 * |-- Netlink -->|                   |                  |
 * |              |- ndo_apf_set_id ->|                  |
 * |              |                   |------ RPC ------>|
 * |              |                   |                  |-- apf_set_id()
 * |              |                   |<---- Success ----|
 * |              |<---- Success -----|                  |
 * |<-- Success --|                   |                  |
 * |              |                   |                  |
 * |-- Netlink -->|                   |                  |
 * |              |- ndo_apf_enable ->|    (interface)   |
 * |              |                   |------ RPC ------>|
 * |              |                   |                  |-- apf_enable()
 * |              |                   |                  |    |-- apf_allocate_state()
 * |              |                   |<---- Success ----| <--'
 * |              |<---- Success -----|                  |
 * |<-- Success --|                   |                  |
 * |              |                   |                  |
 * |              |                   |           [Packet Ingress]
 * |              |                   |                  |    |
 * |              |                   |                  |    |-- apf_run_header(state, hdr2, vlan_tag, hdr3)
 * |              |                   |                  |    '-- apf_run_packet(state, pkt, len)
 * |              |                   |                  |
 * |-- Netlink -->|                   |                  |
 * |              |- ndo_apf_disable->|    (interface)   |
 * |              |                   |------ RPC ------>|
 * |              |                   |                  |-- apf_disable(state)
 * |              |                   |                  |    |-- apf_free_state()
 * |              |                   |<---- Success ----| <--'
 * |              |<---- Success -----|                  |
 * |<-- Success --|                   |                  |
 *
 * Note: netlink is always in the context of a netdev, as this is
 * required to reach the right driver.  However, neither apf_get_info()
 * nor apf_set_id() require an interface/context at the firmware level.
 * They're simply talking to the APF interpreter embedded in that chip.
 * (a driver capable of handling multiple chips must take care to talk
 * to the right one)
 *
 * apf_enable() allocates an apf_state for that netdev/interface,
 * this is stored within the firmware, the driver/firmware must
 * keep track of this mapping.
 *
 * Everything else is per netdev/interface and requires that apf_state.
 */

/*****************************************
 * Firmware configuration (customizable) *
 *****************************************/

/**
 * Setting APF_DEBUG to 1 will enable extra runtime checks, which will
 * result in slightly lower performance.
 * It is recommended to set to 1 for debug builds, and 0 for production builds.
 */
#ifndef APF_DEBUG
#define APF_DEBUG 1
#endif

/**
 * Setting APF_LOCK to 1 will enable calls to apf_global_lock() / apf_global_unlock().
 * If it is 0, these calls are skipped and the apf interpreter must be run fully
 * single threaded.
 * Even when APF_LOCK is 1 the firmware must still guarantee that there are no
 * concurrent calls to the apf interpreter on a single apf_state object (ie.
 * a single network interface).
 */
#ifndef APF_LOCK
#define APF_LOCK 1
#elif APF_LOCK == 0
#undef APF_LOCK
#endif

/**
 * This macro definition can be adjusted by the firmware, but must be:
 *  - a power of two,
 *  - at least 4,
 *  - at most 256,
 *  - a multiple of the alignment of a uint64_t (within a struct),
 *  - a multiple of the alignment of a pointer.
 * It is a characteristic of the available memory architecture & allocator.
 */
#ifndef APF_MEMORY_ALLOCATION_GRANULARITY
#define APF_MEMORY_ALLOCATION_GRANULARITY 8
#endif

/**
 * This is the total amount of ram available for apf_state's.  This must be at least 8192.
 * The total sum of all outstanding apf_allocate_state() calls will never exceed this value.
 * (Note: this memory does not include ingress/egress packet buffers)
 */
#ifndef APF_STATE_MEMORY_TOTAL_LIMIT
#define APF_STATE_MEMORY_TOTAL_LIMIT 16384
#endif

/**
 * Pointers to this struct are passed to all firmware hooks.
 * At minimum this identifies an interface
 * (whatever is the firmware equivalent of a Linux Kernel netdev)
 *
 * It is up to the firmware to define this struct.
 */
struct apf_fw_ctx;

/**************************************************
 * Firmware hooks (to be implemented by firmware) *
 **************************************************/

#if APF_LOCK

/**
 * Called by the interpreter to acquire the APF firmware global lock.
 * This ensures exclusive access to the firmware's global APF state.
 * On a single-threaded implementation, this may do nothing.
 */
void apf_global_lock(void);

/**
 * Called by the interpreter to release the APF firmware global lock.
 * On a single-threaded implementation, this may do nothing.
 */
void apf_global_unlock(void);

#endif

/**
 * Returns the number of apf ticks (1/16384ths of a second) since some arbitrary point in time,
 * likely firmware cpu bootup/reset.
 * This should be a monotonically increasing clock source at a constant rate of 16K ticks/second.
 * This function may be called while holding APF firmware global lock.
 *
 * NOTE: How to calculate ticks:
 *
 * - if you have a u64 clock source counting nanoseconds:
 *     u64 nanoseconds = current_nanosecond_time_u64();
 *     u32 ticks = (u32)((nanoseconds << 5) / 1953125);
 *
 * - if you have a u64 clock source counting microseconds:
 *     u64 microseconds = current_microsecond_time_u64();
 *     u32 ticks = (u32)((microseconds << 8) / 15625);
 *
 * - if you have a u64 clock source counting milliseconds:
 *     u64 milliseconds = current_millisecond_time_u64();
 *     u32 ticks = (u32)((milliseconds << 11) / 125);
 *
 * - if you have a u32 clock source counting milliseconds and cannot use 64-bit arithmetic:
 *     u32 milliseconds = current_millisecond_time_u32();
 *     u32 ticks = ((((((milliseconds << 4) / 5) << 2) / 5) << 2) / 5) << 3;
 *   or the less precise:
 *     u32 ticks = ((milliseconds << 4) / 125) << 7;
 */
uint32_t apf_get_time_in_ticks(void);

/**
 * Called by the interpreter to schedule the next timer event.
 *
 * @param relative_ticks - number of ticks from now when the timer should fire.
 *                         0 means fire immediately (call apf_process_timer_event).
 *                         0xFFFFFFFF means no timer scheduled.
 * @param precision_ticks - the timer can be delayed by up to this many extra ticks.
 */
void apf_set_timer(uint32_t relative_ticks, uint32_t precision_ticks);

/**
 * This function is provided by the firmware, and is called by apf_enable()
 * to allocate the memory backing an apf_state.
 * size will always be a multiple of APF_MEMORY_ALLOCATION_GRANULARITY.
 * ctx will be exactly what was passed as the ctx to apf_enable().
 * A trivial implementation may simply be 'return malloc(size)'.
 * The returned pointer must satisfy the alignment of a uint64_t,
 * with a minimum alignment of 4 bytes.
 * In very rare situations this may return NULL due to OOM.
 */
void *apf_allocate_state(struct apf_fw_ctx* ctx, uint32_t size);

/*
 * This function is provided by the firmware, and is called by apf_disable()
 * to deallocate an apf_state.
 * fw_ctx will match that provided at allocation time.
 * ptr will be the precise value returned by a previous apf_allocate_state() call.
 * size will be the precise value passed to that allocation call.
 * A trivial implementation may simply be 'free(ptr)'.
 */
void apf_free_state(struct apf_fw_ctx* ctx, void* ptr, uint32_t size);

/**
 * Allocates a buffer for the APF program to build a reply packet.
 *
 * Unless in a critical low memory state, the firmware must allow allocating at
 * least one 1514 byte buffer for every call to apf_run_packet(). The interpreter will
 * have at most one active allocation at any given time, and will always either
 * transmit or deallocate the buffer before apf_run_packet() returns.
 *
 * It is OK if the firmware decides to limit allocations to at most one per
 * apf_run_packet() invocation. This allows the firmware to delay transmitting
 * the buffer until after apf_run_packet() has returned (by keeping track of whether
 * a buffer was allocated/deallocated/scheduled for transmit) and may
 * allow the use of a single statically allocated 1514+ byte buffer.
 *
 * The firmware MAY choose to allocate a larger buffer than requested, and
 * give the apf_interpreter a pointer to the middle of the buffer. This will
 * allow firmware to later (during or after apf_transmit_tx_buffer call) populate
 * any required headers, trailers, etc.
 *
 * @param ctx - unmodified ctx pointer passed into apf_enable().
 * @param size - the minimum size of buffer to allocate
 * @return the pointer to the allocated region. The function can return NULL to
 *         indicate allocation failure, for example if too many buffers are
 *         pending transmit. Returning NULL will most likely result in
 *         apf_run_packet() returning PASS.
 */
uint8_t *apf_allocate_tx_buffer(struct apf_fw_ctx *ctx, uint32_t size);

/**
 * Allocates a buffer for the APF program to build a packet to send to cpu.
 *
 * Exactly like apf_allocate_tx_buffer() but for ingress direction.
 *
 * May have the same implementation if the firmware does not care about
 * using different portions of memory depending on direction.
 */
uint8_t *apf_allocate_rx_buffer(struct apf_fw_ctx *ctx, uint32_t size);

/**
 * Transmit destination type for egress packets.
 */
typedef enum {
    /** Send to all clients of the AP */
    MULTICAST,
    /** Send to the source of the packet that triggered this execution */
    UNICAST_RETURN,
    /**
     * Send to specific client MAC (can be triggered from a timer,
     * so there may be no triggering client).
     */
    UNICAST_OTHER,
} apf_transmit_type;

/**
 * Transmits the allocated buffer and deallocates it.
 *
 * The apf_interpreter will not read/write from/to the buffer once it calls
 * this function.
 *
 * The content of the buffer between [ptr, ptr + len) are the bytes to be
 * transmitted, starting from the ethernet header and not including any
 * ethernet CRC bytes at the end.
 *
 * The firmware is expected to make its best effort to transmit. If it
 * exhausts retries, or if there is no channel for too long and the transmit
 * queue is full, then it is OK for the packet to be dropped. The firmware should
 * prefer to fail allocation if it can predict transmit will fail.
 *
 * apf_transmit_tx_buffer() may be asynchronous, which means the actual packet
 * transmission can happen sometime after the function returns.
 *
 * @param ctx - unmodified ctx pointer passed into apf_enable().
 * @param ptr - pointer to the transmit buffer, must have been previously
 *              returned by apf_allocate_tx_buffer() and not deallocated.
 * @param len - the number of bytes to be transmitted (possibly less than
 *              the allocated buffer), 0 means don't transmit the buffer
 *              but only deallocate it.
 * @param dscp - value in [0..63] - the upper 6 bits of the TOS field in
 *               the IPv4 header or traffic class field in the IPv6 header.
 * @param type - the transmit destination type (MULTICAST, UNICAST_RETURN, UNICAST_OTHER).
 *               For APF in STA mode this parameter MUST be ignored, since all packets
 *               need to be sent via wifi unicast to the AP anyway.
 * @return non-zero if the firmware *knows* the transmit will fail, zero if
 *         the transmit succeeded or the firmware thinks it will succeed.
 *         Returning an error will likely result in apf_run_packet() returning PASS.
 */
int apf_transmit_tx_buffer(struct apf_fw_ctx *ctx, uint8_t *ptr, uint32_t len, uint8_t dscp,
                            apf_transmit_type type);

/**
 * Transmits (to the CPU) the allocated buffer and deallocates it.
 *
 * Exactly like apf_transmit_rx_buffer() but for ingress direction.
 *
 * May be delivered to the kernel driver via some out of band control path
 * mechanism, and injected as a received packet.
 *
 * dscp is not expected to be useful, but provided to mirror tx.
 */
int apf_transmit_rx_buffer(struct apf_fw_ctx *ctx, uint8_t *ptr, uint32_t len, uint8_t dscp);

/****************************************
 * APF core definitions (do not modify) *
 ****************************************/

/**
 * APF measures time in 'apf ticks' - ie. units of 1/16384ths of a second.
 */
#define APF_TICKS_PER_SECOND_LOG2 14
#define APF_TICKS_PER_SECOND (1 << APF_TICKS_PER_SECOND_LOG2)

/**
 * This structure is returned via apf_get_info()
 */
struct apf_info {
    uint32_t apf_version;  // for example 6100 means APFv6.1
    uint32_t apf_id;       // defaults to 0 at bootup
    uint32_t total_ram;    // in bytes
    uint32_t used_ram;     // in bytes
    uint32_t overhead;     // in bytes
    uint32_t granularity;  // in bytes
};

/**
 * Opaque data structure storing internal per-interface APF state.
 */
struct apf_state;

/**********************************
 * APF API (for firmware to call) *
 **********************************/

/*
 * Firmware implementation backing driver's netdev_ops->ndo_apf_get_info(apf_info *info)
 * apf_info is an output-only argument that needs to be returned to the driver.
 */
void apf_get_info(struct apf_info *info);

/**
 * Firmware implementation backing driver's netdev_ops->ndo_apf_set_id(uint32_t id)
 */
void apf_set_id(uint32_t id);

/**
 * Firmware implementation backing driver's netdev_ops->ndo_apf_enable(uint32_t ram_size)
 * fw_ctx (cannot be NULL, uniquely identifies the network interface),
 * will be remembered by apf in the apf_state, and passed through to all other calls.
 * Will return NULL on memory exhaustion.
 * After this function returns non-NULL non-fast-path ingress must go via apf_run_header()/apf_run_packet()
 * This will return a pointer returned by apf_allocate_state(fw_ctx, overhead + ram_size + …)
 */
struct apf_state *apf_enable(struct apf_fw_ctx *ctx, uint32_t ram_size);

/**
 * Firmware implementation backing driver's netdev_ops->ndo_apf_get_ram_size()
 * (will return 0 if called with NULL)
 */
uint32_t apf_get_ram_size(const struct apf_state *state);

/**
 * Read from APF RAM (at an offset) into a buffer 'buf' of length 'length'
 */
int apf_read(const struct apf_state *state, uint32_t offset, uint8_t *buf, uint32_t length);

/**
 * Write from a buffer 'buf' of length 'length' into APF RAM (at an offset)
 * Firmware should not assign any meaning nor perform any validation of offset,
 * for example an offset of -1 is used to represent program installation.
 */
int apf_write(struct apf_state *state, int32_t offset, const uint8_t *buf, uint32_t length);

/**
 * Firmware implementation backing driver's netdev_ops->ndo_apf_disable()
 * Before you call this you should stop calling apf_run_header()/apf_run_packet() with this apf_state.
 * Will call apf_free_state(fw_ctx, ptr, same_size_as_was_allocated)
 * This also needs to be called when a netdev 'vanishes' without a clean shutdown.
 */
void apf_disable(struct apf_state *state);

/**
 * Called during Linux kernel's suspend/resume.
 * Allows APF interpreter to enable more expensive and aggressive filtering during suspend.
 */
void apf_suspend(struct apf_state *state);
void apf_resume(struct apf_state *state);

/**
 * Returns number of ticks to sleep before calling apf_process_timer_event()
 * If it returns 0 then call it immediately
 * If precision is not NULL, the next call can be delayed by up to precision extra ticks.
 * Ticks can be converted to other units via:
 *   u32 next = apf_ticks_until_next_timer_event(NULL);
 *   u32 seconds = next >> APF_TICKS_PER_SECOND_LOG2;
 *   next &= (APF_TICKS_PER_SECOND - 1);
 * and then one of:
 *   u32 nanoseconds = next * 61035;
 *   u32 microseconds = next * 61;
 *   u32 milliseconds = (next * 125) >> 11;
 */
uint32_t apf_ticks_until_next_timer_event(uint32_t *precision);

/**
 * Firmware is required to call this on timer expiration.
 * Each call will handle a single timer event,
 * and may generate a small number of egress and ingress packets.
 * Will return true if more events need to be processed (now!).
 * Possibly should be invoked as:
 *   while (apf_process_timer_event()) if_needed_do_tx_and_rx_flush();
 * Only the final call (which returns false) will arm the next timer via apf_set_timer().
 */
bool apf_process_timer_event(void);

/**
 * Runs the installed APF program over a full packet.
 *
 * The return value of apf_run_packet indicates whether the packet should
 * be passed or dropped. As a part of execution, the APF program can call
 * apf_allocate_tx_buffer() and apf_transmit_tx_buffer() to construct and
 * transmit a reply packet.
 *
 * @param state - non-NULL state returned by apf_enable(). The caller must not
 *                make concurrent calls using the same state.
 * @param packet - the full packet bytes, starting from the ethernet header.
 * @param packet_len - the length of {@code packet} in bytes, not
 *                     including trailers/CRC.
 *
 * @return zero if packet should be dropped,
 *         non-zero if packet should be passed, specifically:
 *         - 1 on normal apf program execution,
 *         - 2 on exceptional circumstances (caused by bad firmware integration),
 *           these include:
 *             - state pointer which is a null pointer
 *             - packet pointer which is a null pointer
 *             - packet_len shorter than ETH_HLEN (14)
 *           As such, you may want to log a firmware exception if 2 is ever returned...
 */
int apf_run_packet(struct apf_state *state, const uint8_t *const packet,
                   const uint32_t packet_len);

/*
 * NOTE: we plan to support packet pre-filtering via apf_run_header():
 *
 * Packet pre-filtering, based on 58 (14 ethernet + 40 ipv6 + 4 src/dport) bytes?
 * This will never trigger packet transmission (inbound/outbound).
 * Returns:
 *   ACCEPT(0)
 *   DROP(1)
 *   CONTINUE(2 - in which case it will prepopulate some memory slots) with apf_run_packet()
 *   ERROR(3+) meaning ACCEPT
 * int apf_run_header(struct apf_state *state,
 *                    const u8 *const ether_hdr,  [14..18 bytes]
 *                    int vlan_tag,
 *                    const u8 *const packet_hdr, [44 bytes] [const u32 pkt_hdr_len]);
 */

#ifdef __cplusplus
}
#endif

#endif  /* APF_INTERPRETER_H_ */
