/*
 * Copyright 2024, The Android Open Source Project
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

#ifdef __KERNEL__
  #include <linux/stddef.h>  // For offsetof
  #include <linux/string.h>  // For memcmp, memcpy, memset
  #include <linux/compiler.h>
#else
  #include <stddef.h>  // For offsetof
  #include <string.h>  // For memcmp, memcpy, memset
#endif

#include "apf_interpreter.h"

#ifndef APF_LOCK
static inline void apf_global_lock(void) {};
static inline void apf_global_unlock(void) {};
#endif

// C99 static assert, replace with _Static_assert() when we switch to C11.
#define APF_STATIC_ASSERT_CONCAT_INNER(a, b) a##b
#define APF_STATIC_ASSERT_CONCAT(a, b) APF_STATIC_ASSERT_CONCAT_INNER(a, b)
#define APF_STATIC_ASSERT(cond) \
    typedef char APF_STATIC_ASSERT_CONCAT(static_assertion_, __LINE__)[(cond) ? 1 : -1]

// Verify requirements of apf_interpreter.h
#ifndef APF_MEMORY_ALLOCATION_GRANULARITY
#error "APF_MEMORY_ALLOCATION_GRANULARITY undefined"
#endif

#if APF_MEMORY_ALLOCATION_GRANULARITY < 4
#error "APF_MEMORY_ALLOCATION_GRANULARITY must be at least 4"
#endif

#if APF_MEMORY_ALLOCATION_GRANULARITY > 256
#error "APF_MEMORY_ALLOCATION_GRANULARITY must be at most 256"
#endif

#if APF_MEMORY_ALLOCATION_GRANULARITY & (APF_MEMORY_ALLOCATION_GRANULARITY - 1)
#error "APF_MEMORY_ALLOCATION_GRANULARITY must be a power of two"
#endif

// Verify APF_MEMORY_ALLOCATION_GRANULARITY is a multiple of alignof(uint64_t) via offsetof trick
struct apf_u64_align_check { char c; uint64_t v; };
APF_STATIC_ASSERT(!(APF_MEMORY_ALLOCATION_GRANULARITY % offsetof(struct apf_u64_align_check, v)));

// Verify APF_MEMORY_ALLOCATION_GRANULARITY is a multiple of alignof(void*) via offsetof trick
struct apf_ptr_align_check { char c; void *v; };
APF_STATIC_ASSERT(!(APF_MEMORY_ALLOCATION_GRANULARITY % offsetof(struct apf_ptr_align_check, v)));

#ifndef APF_STATE_MEMORY_TOTAL_LIMIT
#error "APF_STATE_MEMORY_TOTAL_LIMIT undefined"
#endif

#if APF_STATE_MEMORY_TOTAL_LIMIT < 8192
#error "APF_STATE_MEMORY_TOTAL_LIMIT must be at least 8192"
#endif

#if APF_STATE_MEMORY_TOTAL_LIMIT > 1048576
#error "APF_STATE_MEMORY_TOTAL_LIMIT must be at most 1048576"
#endif

#if APF_DEBUG == 0
#undef APF_DEBUG
#endif

#if APF_TICKS_PER_SECOND_LOG2 != 14
#error "APF_TICKS_PER_SECOND_LOG2 must be 14"
#endif

#if APF_TICKS_PER_SECOND != 16384
#error "APF_TICKS_PER_SECOND must be 16384"
#endif

#ifdef __KERNEL__
  #define FOR_KERNEL(v) EXPORT_SYMBOL(v);
  #define FALLTHROUGH fallthrough
#else
  #define FOR_KERNEL(v)
  #if __GNUC__ >= 7 || __clang__
    #define FALLTHROUGH __attribute__((fallthrough))
  #else
    #define FALLTHROUGH
  #endif
#endif

#include "apf_defs.h"
#include "apf.h"
#include "apf_utils.h"
#include "apf_dns.h"
#include "apf_checksum.h"

#define APF_VERSION 20260420

// User hook for interpreter debug tracing.
#ifdef APF_TRACE_HOOK
extern void APF_TRACE_HOOK(u32 pc, const u32* regs, const u8* program,
                           u32 program_len, const u8 *packet, u32 packet_len,
                           const u32* memory, u32 ram_len);
#else
#define APF_TRACE_HOOK(pc, regs, program, program_len, packet, packet_len, memory, memory_len) \
    do { /* nop*/                                                                              \
    } while (0)
#endif

// Return code indicating "packet" should accepted.
#define PASS 1
// Return code indicating "packet" should be accepted (and something unexpected happened).
#define EXCEPTION 2
// Return code indicating "packet" should be dropped.
#define DROP 0
// Verify an internal condition and accept packet if it fails.
#define ASSERT_RETURN(c) if (!(c)) return EXCEPTION
// If "c" is of an unsigned type, generate a compile warning that gets promoted to an error.
// This makes bounds checking simpler because ">= 0" can be avoided. Otherwise adding
// superfluous ">= 0" with unsigned expressions generates compile warnings.
#define ENFORCE_UNSIGNED(c) ((c)==(u32)(c))

static u32 apf_id = 0;
static u32 apf_used_ram = 0;

static struct apf_state *apf_state_list_head = NULL;

struct apf_state {
    struct apf_state *next;
    struct apf_state *prev;
    struct apf_fw_ctx *ctx;
    u32 ram_size;
    u32 next_timer_abs;
    u32 timer_precision;
    u32 program_len;
    u32 program_install_time;
    bool suspended;
    bool timer_set;
    u8 pad[2];
    u8 ram[];
};

typedef struct {
    // Note: the following 4 fields take up exactly 8 bytes.
    u16 except_buf_sz; // Length of the exception buffer (at program_len offset)
    u8 ptr_size;       // sizeof(void*)
    u8 v6;             // Set to 1 by first jmpdata (APFv6+) instruction
    u32 pc;            // Program counter.
    // All the pointers should be next to each other for better struct packing.
    // We are at offset 8, so even 64-bit pointers will not need extra padding.
    struct apf_fw_ctx *caller_ctx; // Passed in to interpreter, passed through to alloc/transmit.
    u8* tx_buf;        // The output buffer pointer
    u8* program;       // Pointer to program/data buffer
    const u8* packet;  // Pointer to input packet buffer
    // Order fields in order of decreasing size
    u32 tx_buf_len;    // The length of the output buffer
    u32 program_len;   // Length of the program
    u32 ram_len;       // Length of the entire apf program/data region
    u32 packet_len;    // Length of the input packet buffer
    u32 R[2];          // Register values.
    memory_type mem;   // Memory slot values.  (array of u32s)
    // Note: any extra u16s go here, then u8s
} apf_context;

// The APF ram section immediately follows the apf_state struct.
// This static assert ensures that the ram section is u32 aligned.
APF_STATIC_ASSERT(!(sizeof(struct apf_state) % sizeof(u32)));

void apf_get_info(struct apf_info *info) {
    if (!info) return;
    apf_global_lock();
    info->apf_version = APF_VERSION;
    info->apf_id = apf_id;
    info->total_ram = APF_STATE_MEMORY_TOTAL_LIMIT;
    info->used_ram = apf_used_ram;
    info->overhead = sizeof(struct apf_state);
    info->granularity = APF_MEMORY_ALLOCATION_GRANULARITY;
    apf_global_unlock();
}
FOR_KERNEL(apf_get_info)

void apf_set_id(u32 id) {
    apf_global_lock();
    apf_id = id;
    apf_global_unlock();
}
FOR_KERNEL(apf_set_id)

struct apf_state *apf_enable(struct apf_fw_ctx *ctx, u32 ram_size) {
    if (ram_size > 65535) return NULL;
    if (ram_size > APF_STATE_MEMORY_TOTAL_LIMIT) return NULL;

    u32 total_size = sizeof(struct apf_state) + ram_size;

    // Round up total_size to a multiple of APF_MEMORY_ALLOCATION_GRANULARITY.
    // This is required by apf_allocate_state() and ensures we use all allocated memory.
    total_size += APF_MEMORY_ALLOCATION_GRANULARITY - 1;
    total_size &= ~(u32)(APF_MEMORY_ALLOCATION_GRANULARITY - 1);

    // We recalculate how much actual space we'll have for ram post round-up.
    ram_size = total_size - sizeof(struct apf_state);

    apf_global_lock();
    if (apf_used_ram + total_size > APF_STATE_MEMORY_TOTAL_LIMIT) {
        apf_global_unlock();
        return NULL;
    }
    apf_used_ram += total_size;
    apf_global_unlock();

    struct apf_state *state = apf_allocate_state(ctx, total_size);
    if (!state) {
        apf_global_lock();
        apf_used_ram -= total_size;
        apf_global_unlock();
        return NULL;
    }

    memset(state, 0, total_size);

    state->ctx = ctx;
    state->ram_size = ram_size;
    // state->suspended = false;
    // state->timer_set = false;
    // state->next_timer_abs = 0;
    // state->timer_precision = 0;
    // state->program_len = 0;
    // memset(state->ram, 0, state->ram_size);

    apf_global_lock();
    // state->prev = NULL;
    state->next = apf_state_list_head;
    if (apf_state_list_head) apf_state_list_head->prev = state;
    apf_state_list_head = state;
    apf_global_unlock();

    return state;
}
FOR_KERNEL(apf_enable)

uint32_t apf_get_ram_size(const struct apf_state *state) {
    return state ? state->ram_size : 0;
}
FOR_KERNEL(apf_get_ram_size)

// TODO - think about what this should return
int apf_read(const struct apf_state *state, u32 offset, u8 *buf, u32 length) {
    if (!state) return -1;
    if (!buf) return -1;
    if (offset + length < offset) return -1;
    if (offset + length > state->ram_size) return -1;
    memcpy(buf, &state->ram[offset], length);
    return 0;
}
FOR_KERNEL(apf_read)

// TODO - think about what this should return
int apf_write(struct apf_state *state, s32 offset, const u8 *buf, u32 length) {
    if (!state) return -1;
    if (!buf) return -1;
    if (offset < -1) return -1;  // not yet handled
    if (offset == -1) {
        if (length > state->ram_size) return -1;
        state->program_len = 0;  // TODO maybe only ifdef APF_LOCK
        memcpy(state->ram, buf, length);
        state->program_install_time = apf_get_time_in_ticks();
        state->program_len = length;
        return 0;
    }
    if ((u32)offset + length < (u32)offset) return -1;
    if ((u32)offset + length > state->ram_size) return -1;
    memcpy(&state->ram[offset], buf, length);
    return 0;
}
FOR_KERNEL(apf_write)

static bool apf_global_timer_set = false;
static u32 apf_global_next_timer_abs = 0;
static u32 apf_global_timer_precision = 0;

static u32 do_apf_ticks_until_next_timer_event(u32 *precision) {
    if (!apf_global_timer_set) {
        if (precision) *precision = 0;
        return 0xFFFFFFFF;
    }

    u32 current_time = apf_get_time_in_ticks();
    s32 diff = (s32)(apf_global_next_timer_abs - current_time);

    if (precision) *precision = apf_global_timer_precision;

    if (diff <= 0) return 0;
    return (u32)diff;
}

u32 apf_ticks_until_next_timer_event(u32 *precision) {
    apf_global_lock();
    u32 ret = do_apf_ticks_until_next_timer_event(precision);
    apf_global_unlock();
    return ret;
}
FOR_KERNEL(apf_ticks_until_next_timer_event)

// Assumes times a and b are not too far (~1.51 days) apart
static bool before(u32 a, u32 b) {
    return (s32)(a - b) < 0;
}

// TODO: needs another thorough code review
static void apf_recalculate_global_timer(void) {
    bool any_timer_set = false;
    u32 timer_abs = 0;
    u32 precision = 0xFFFFFFFF;

    apf_global_lock();
    for (struct apf_state *state = apf_state_list_head; state; state = state->next) {
        if (!state->timer_set) continue;

        if (!any_timer_set) {
            any_timer_set = true;
            timer_abs = state->next_timer_abs;
            precision = state->timer_precision;
        } else {
            if (before(state->next_timer_abs + state->timer_precision, timer_abs + precision)) {
                precision = state->next_timer_abs + state->timer_precision - timer_abs;
            }

            if (before(state->next_timer_abs, timer_abs)) timer_abs = state->next_timer_abs;
        }
    }

    if (any_timer_set) {
        bool need_to_arm = !apf_global_timer_set
            || (apf_global_next_timer_abs != timer_abs)
            || (apf_global_timer_precision != precision);

        apf_global_timer_set = any_timer_set;
        apf_global_next_timer_abs = timer_abs;
        apf_global_timer_precision = precision;

        if (need_to_arm) {
            u32 current_time = apf_get_time_in_ticks();
            s32 diff = (s32)(timer_abs - current_time);
            if (diff < 0) diff = 0;

            apf_global_unlock();
            apf_set_timer((u32)diff, precision);
            return;
        }
    } else {
        if (apf_global_timer_set) {
            apf_global_timer_set = false;
            apf_global_unlock();
            // TODO: maybe don't call just store to global or return this?
            // then this function can be called with lock held
            apf_set_timer(0xFFFFFFFF, 0);
            return;
        }
    }
    apf_global_unlock();
}

void apf_disable(struct apf_state *state) {
    if (!state) return;

    u32 total_size = sizeof(struct apf_state) + state->ram_size;
    struct apf_fw_ctx *ctx = state->ctx;

    apf_global_lock();
    if (state->prev) {
        state->prev->next = state->next;
    } else {
        apf_state_list_head = state->next;
    }
    if (state->next) state->next->prev = state->prev;

    apf_used_ram -= total_size;
    apf_global_unlock();

    apf_free_state(ctx, state, total_size);

    apf_recalculate_global_timer();
}
FOR_KERNEL(apf_disable)

void apf_suspend(struct apf_state *state) {
    if (!state) return;
    if (state->suspended) return;
    state->suspended = true;
    // TODO: may need to call into bytecode and/or recalculate timers
}
FOR_KERNEL(apf_suspend)

void apf_resume(struct apf_state *state) {
    if (!state) return;
    if (!state->suspended) return;
    state->suspended = false;
    // TODO: may need to call into bytecode and/or recalculate timers
}
FOR_KERNEL(apf_resume)

// TODO: require lock to be held when called
static bool do_apf_process_timer_event(u32 current_time) {
    apf_global_lock();
    for (struct apf_state *state = apf_state_list_head; state; state = state->next) {
        if (!state->timer_set) continue;

        // If the next timer is in the future (accounting for wrap-around), stop processing.
        if (before(current_time, state->next_timer_abs)) continue;

        // TODO: Implement the actual trigger timer logic for 'state' here.
        // For example, executing a specific APF handler or program.

        // Clear the timer for this state to prevent an infinite loop.
        // The APF program is responsible for setting a new timer if needed.
        state->timer_set = false;
        apf_global_unlock();
        return true;
    }
    apf_global_unlock();
    apf_recalculate_global_timer();
    return false;
}

bool apf_process_timer_event(void) {
    u32 current_time = apf_get_time_in_ticks();
    // TODO: apf_global_lock();
    bool v = do_apf_process_timer_event(current_time);
    // TODO: apf_global_unlock();
    return v;
}
FOR_KERNEL(apf_process_timer_event)

static inline int do_transmit_buffer(apf_context *ctx, u32 pkt_len, u8 dscp) {
    int ret = apf_transmit_tx_buffer(ctx->caller_ctx, ctx->tx_buf, pkt_len, dscp, UNICAST_RETURN);
    ctx->tx_buf = NULL;
    ctx->tx_buf_len = 0;
    return ret;
}

static inline int do_discard_buffer(apf_context *ctx) {
    return do_transmit_buffer(ctx, 0 /* pkt_len */, 0 /* dscp */);
}

#define DECODE_U8() (ctx->program[ctx->pc++])

static inline u16 decode_be16(apf_context *ctx) {
    u16 v = DECODE_U8();
    v <<= 8;
    v |= DECODE_U8();
    return v;
}

// Decode an immediate, lengths [0..4] all work, does not do range checking.
// But note that program is at least 20 bytes shorter than ram, so first few
// immediates can always be safely decoded without exceeding ram buffer.
static inline u32 decode_imm(apf_context *ctx, u32 length) {
    u32 v = 0;
    for (u32 i = 0; i < length; ++i) v = (v << 8) | DECODE_U8();
    return v;
}

// Warning: 'ofs' should be validated by caller!
static inline u8 read_packet_u8(apf_context *ctx, u32 ofs) {
    return ctx->packet[ofs];
}

static int do_apf_run(apf_context *ctx) {
// Is offset within ram bounds?
#define IN_RAM_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < ctx->ram_len)
// Is offset within packet bounds?
#define IN_PACKET_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < ctx->packet_len)
// Is access to offset |p| length |size| within data bounds?
#define IN_DATA_BOUNDS(p, size) (ENFORCE_UNSIGNED(p) && \
                                 ENFORCE_UNSIGNED(size) && \
                                 (p) + (size) <= ctx->ram_len && \
                                 (p) + (size) >= (p))  // catch wraparounds
// Accept packet if not within ram bounds
#define ASSERT_IN_RAM_BOUNDS(p) ASSERT_RETURN(IN_RAM_BOUNDS(p))
// Accept packet if not within packet bounds
#define ASSERT_IN_PACKET_BOUNDS(p) ASSERT_RETURN(IN_PACKET_BOUNDS(p))
// Accept packet if not within data bounds
#define ASSERT_IN_DATA_BOUNDS(p, size) ASSERT_RETURN(IN_DATA_BOUNDS(p, size))

    // Counters start at end of RAM and count *backwards* so this array takes negative integers.
    u32 *counter = (u32*)(ctx->program + ctx->ram_len);

    // Count of instructions remaining to execute. This is done to ensure an
    // upper bound on execution time. It should never be hit and is only for
    // safety. Initialize to the number of bytes in the program which is an
    // upper bound on the number of instructions in the program.
    u32 instructions_remaining = ctx->program_len;

    // APFv6.1 requires at least 6 u32 counters at the end of ram, this makes counter[-6]++ valid
    // This cannot wrap due to previous check, that enforced program_len & ram_len < 2GiB.
    if (ctx->program_len + 24 > ctx->ram_len) return EXCEPTION;

    // Only populate if packet long enough, and IP version is IPv4.
    // Note: this doesn't actually check the ethertype...
    if ((ctx->packet_len >= ETH_HLEN + IPV4_HLEN)
        && ((read_packet_u8(ctx, ETH_HLEN) & 0xf0) == 0x40)) {
        ctx->mem.named.ipv4_header_size = (read_packet_u8(ctx, ETH_HLEN) & 15) * 4;
    }

// Is access to offset |p| length |size| within output buffer bounds?
#define IN_OUTPUT_BOUNDS(p, size) (ENFORCE_UNSIGNED(p) && \
                                 ENFORCE_UNSIGNED(size) && \
                                 (p) + (size) <= ctx->tx_buf_len && \
                                 (p) + (size) >= (p))
// Accept packet if not write within allocated output buffer
#define ASSERT_IN_OUTPUT_BOUNDS(p, size) ASSERT_RETURN(IN_OUTPUT_BOUNDS(p, size))

    do {
      APF_TRACE_HOOK(ctx->pc, ctx->R, ctx->program, ctx->program_len,
                     ctx->packet, ctx->packet_len, ctx->mem.slot, ctx->ram_len);
      if (ctx->pc >= ctx->program_len) {
          u32 ofs = ctx->pc - ctx->program_len;
          u32 imm = ofs >> 1;
          if (imm > 0xFFFF) return EXCEPTION;
          if (imm) {
              if (4 * imm > ctx->ram_len) return EXCEPTION;
              counter[-(s32)imm]++;
          }
          return (ofs & 1) ? DROP : PASS;
      }

      {  // half indent to avoid needless line length...

        const u8 bytecode = DECODE_U8();
        const u8 opcode = EXTRACT_OPCODE(bytecode);
        const u8 reg_num = EXTRACT_REGISTER(bytecode);
#define REG (ctx->R[reg_num])
#define OTHER_REG (ctx->R[reg_num ^ 1])
        // All instructions have immediate fields, so load them now.
        const u8 len_field = EXTRACT_IMM_LENGTH(bytecode);
        const u8 imm_len = ((len_field + 1u) >> 2) + len_field; // 0,1,2,3 -> 0,1,2,4
        u32 pktcopy_src_offset = 0;  // used for various pktdatacopy opcodes
        u32 imm = 0;
        s32 signed_imm = 0;
        u32 arith_imm;
        s32 arith_signed_imm;
        if (len_field != 0) {
            imm = decode_imm(ctx, imm_len); // 1st imm, at worst bytes 1-4 past opcode/program_len
            // Sign extend imm into signed_imm.
            signed_imm = (s32)(imm << ((4 - imm_len) * 8));
            signed_imm >>= (4 - imm_len) * 8;
        }

        // See comment at ADD_OPCODE for the reason for ARITH_REG/arith_imm/arith_signed_imm.
#define ARITH_REG (ctx->R[reg_num & ctx->v6])
        arith_imm = (ctx->v6) ? (len_field ? imm : OTHER_REG) : (reg_num ? ctx->R[1] : imm);
        arith_signed_imm = (ctx->v6) ? (len_field ? signed_imm : (s32)OTHER_REG) : (reg_num ? (s32)ctx->R[1] : signed_imm);

        switch (opcode) {
          case PASSDROP_OPCODE: {  // APFv6+
            if (len_field > 2) return EXCEPTION;  // max 64K counters (ie. imm < 64K)
            if (imm) {
                if (4 * imm > ctx->ram_len) return EXCEPTION;
                counter[-(s32)imm]++;
            }
            return reg_num ? DROP : PASS;
          }
          case LDB_OPCODE:
          case LDH_OPCODE:
          case LDW_OPCODE:
          case LDBX_OPCODE:
          case LDHX_OPCODE:
          case LDWX_OPCODE: {
            u32 load_size = 0;
            u32 offs = imm;
            // Note: this can overflow and actually decrease offs.
            if (opcode >= LDBX_OPCODE) offs += ctx->R[1];
            switch (opcode) {
              case LDB_OPCODE:
              case LDBX_OPCODE:
                load_size = 1;
                break;
              case LDH_OPCODE:
              case LDHX_OPCODE:
                load_size = 2;
                break;
              case LDW_OPCODE:
              case LDWX_OPCODE:
                load_size = 4;
                break;
              // Immediately enclosing switch statement guarantees
              // opcode cannot be any other value.
            }
            const u32 end_offs = offs + (load_size - 1);
            u32 val = 0;
            // Catch overflow/wrap-around.
            ASSERT_RETURN(end_offs >= offs);
            ASSERT_IN_PACKET_BOUNDS(end_offs);
            // load_size underflow on final iteration not an issue as not used after loop.
            while (load_size--) val = (val << 8) | read_packet_u8(ctx, offs++);
            REG = val;
            break;
          }
          case JMP_OPCODE:
            if (reg_num && !ctx->v6) {  // APFv6+
                // First invocation of APFv6 jmpdata instruction
                counter[-1] = 0x12345678;  // endianness marker
                counter[-2]++;  // total packets ++
                ctx->v6 = (u8)true;
            }
            // This can jump backwards. Infinite looping prevented by instructions_remaining.
            ctx->pc += imm;
            break;
          case JEQ_OPCODE:
          case JNE_OPCODE:
          case JGT_OPCODE:
          case JLT_OPCODE:
          case JSET_OPCODE:
          case JNSET_OPCODE: {
            u32 cmp_imm = 0;
            // Load second immediate field.
            if (reg_num == 1) {
                cmp_imm = ctx->R[1];
            } else {
                cmp_imm = decode_imm(ctx, imm_len); // 2nd imm, at worst 8 bytes past prog_len
            }
            switch (opcode) {
              case JEQ_OPCODE:   if (  ctx->R[0] == cmp_imm ) ctx->pc += imm; break;
              case JNE_OPCODE:   if (  ctx->R[0] != cmp_imm ) ctx->pc += imm; break;
              case JGT_OPCODE:   if (  ctx->R[0] >  cmp_imm ) ctx->pc += imm; break;
              case JLT_OPCODE:   if (  ctx->R[0] <  cmp_imm ) ctx->pc += imm; break;
              case JSET_OPCODE:  if (  ctx->R[0] &  cmp_imm ) ctx->pc += imm; break;
              case JNSET_OPCODE: if (!(ctx->R[0] &  cmp_imm)) ctx->pc += imm; break;
            }
            break;
          }
          case JBSMATCH_OPCODE: {
            // Load second immediate field.
            u32 cmp_imm = decode_imm(ctx, imm_len); // 2nd imm, at worst 8 bytes past prog_len
            u32 cnt = (cmp_imm >> 11) + 1; // 1+, up to 32 fits in u16
            u32 len = cmp_imm & 2047; // 0..2047
            u32 bytes = cnt * len;
            const u32 last_packet_offs = ctx->R[0] + len - 1;
            bool matched = false;
            // bytes = cnt * len is size in bytes of data to compare.
            // pc is offset of program bytes to compare.
            // imm is jump target offset.
            // R0 is offset of packet bytes to compare.
            if (bytes > 0xFFFF) return EXCEPTION;
            // pc < program_len < ram_len < 2GiB, thus pc + bytes cannot wrap
            if (!IN_RAM_BOUNDS(ctx->pc + bytes - 1)) return EXCEPTION;
            ASSERT_IN_PACKET_BOUNDS(ctx->R[0]);
            // Note: this will return EXCEPTION (due to wrap) if imm_len (ie. len) is 0
            ASSERT_RETURN(last_packet_offs >= ctx->R[0]);
            ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
            // cnt underflow on final iteration not an issue as not used after loop.
            while (cnt--) {
                matched |= !memcmp(ctx->program + ctx->pc, ctx->packet + ctx->R[0], len);
                // skip past comparison bytes
                ctx->pc += len;
            }
            if (matched ^ !reg_num) ctx->pc += imm;
            break;
          }
          case JBSPTRMATCH_OPCODE: {
            u32 ofs = DECODE_U8();    // 2nd imm, at worst 5 bytes past prog_len
            u8 cmp_imm = DECODE_U8(); // 3rd imm, at worst 6 bytes past prog_len
            u8 cnt = (cmp_imm >> 4) + 1; // 1..16 bytestrings to match
            u8 len = (cmp_imm & 15) + 1; // 1..16 bytestring length
            const u32 last_packet_offs = ofs + len - 1;  // min 0+1-1=0, max 255+16-1=270
            bool matched = false;
            // imm is jump target offset.
            // [ofs..last_packet_offs] are packet bytes to compare.
            ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
            // cnt underflow on final iteration not an issue as not used after loop.
            // 4th (through max 19th) u8 immediates, this reaches at most 22 bytes past prog_len
            // This assumes min ram size of 529 bytes, where APFv6.1 has min ram size of 3000
            // the +3 is to skip over the APFv6 'datajmp' instruction, while 2* to have access to 526 bytes,
            // Primary purpose is for mac (6) & ipv6 (16) addresses, so even offsets should be easy...
            while (cnt--) matched |= !memcmp(ctx->program + 3 + 2 * DECODE_U8(), ctx->packet + ofs, len);
            if (matched ^ !reg_num) ctx->pc += imm;
            break;
          }
          // There is a difference in APFv4 and APFv6 arithmetic behaviour!
          // APFv4:  R[0] op= Rbit ? R[1] : imm;  (and it thus doesn't make sense to have R=1 && len_field>0)
          // APFv6+: REG  op= len_field ? imm : OTHER_REG;  (note: this is *DIFFERENT* with R=1 len_field==0)
          // Furthermore APFv4 uses unsigned imm (except SH), while APFv6 uses signed_imm for ADD/AND/SH.
          case ADD_OPCODE: ARITH_REG += (ctx->v6) ? (u32)arith_signed_imm : arith_imm; break;
          case MUL_OPCODE: ARITH_REG *= arith_imm; break;
          case AND_OPCODE: ARITH_REG &= (ctx->v6) ? (u32)arith_signed_imm : arith_imm; break;
          case OR_OPCODE:  ARITH_REG |= arith_imm; break;
          case DIV_OPCODE: {  // see above comment!
            const u32 div_operand = arith_imm;
            ASSERT_RETURN(div_operand);
            ARITH_REG /= div_operand;
            break;
          }
          case SH_OPCODE: {  // see above comment!
            if (arith_signed_imm >= 0)
                ARITH_REG <<= arith_signed_imm;
            else
                ARITH_REG >>= -arith_signed_imm;
            break;
          }
          case LI_OPCODE:
            REG = (u32)signed_imm;
            break;
          case PKTDATACOPY_OPCODE:
            pktcopy_src_offset = imm;
            imm = PKTDATACOPYIMM_EXT_OPCODE;
            FALLTHROUGH;
          case EXT_OPCODE:
            if (// imm >= LDM_EXT_OPCODE &&  -- but note imm is u32 and LDM_EXT_OPCODE is 0
                imm < (LDM_EXT_OPCODE + MEMORY_ITEMS)) {
                REG = ctx->mem.slot[imm - LDM_EXT_OPCODE];
            } else if (imm >= STM_EXT_OPCODE && imm < (STM_EXT_OPCODE + MEMORY_ITEMS)) {
                ctx->mem.slot[imm - STM_EXT_OPCODE] = REG;
            } else switch (imm) {
              case NOT_EXT_OPCODE: REG = ~REG;      break;
              case NEG_EXT_OPCODE: REG = -REG;      break;
              case MOV_EXT_OPCODE: REG = OTHER_REG; break;
              case SWAP_EXT_OPCODE: {
                u32 tmp = ctx->R[0];
                ctx->R[0] = ctx->R[1];
                ctx->R[1] = tmp;
                break;
              }
              case ALLOCATE_EXT_OPCODE:
              do_allocate:
                ASSERT_RETURN(ctx->tx_buf == NULL);
                if (opcode == ALLOC_XMIT_OPCODE) {
                    ctx->tx_buf_len = 266 + 8 * imm;
                } else if (reg_num == 0) {
                    ctx->tx_buf_len = REG;
                } else {
                    ctx->tx_buf_len = decode_be16(ctx); // 2nd imm, at worst 6 B past prog_len
                }
                // checksumming functions require minimum 266 byte buffer for correctness
                if (ctx->tx_buf_len < 266) ctx->tx_buf_len = 266;
                ctx->tx_buf = apf_allocate_tx_buffer(ctx->caller_ctx, ctx->tx_buf_len);
                if (!ctx->tx_buf) {  // allocate failure
                    ctx->tx_buf_len = 0;
                    counter[-3]++;
                    return EXCEPTION;
                }
                memset(ctx->tx_buf, 0, ctx->tx_buf_len);
                ctx->mem.named.tx_buf_offset = 0;
                break;
              case TRANSMIT_EXT_OPCODE:
              do_transmit: {
                // tx_buf_len cannot be large because we'd run out of RAM,
                // so the above unsigned comparison effectively guarantees casting pkt_len
                // to a signed value does not result in it going negative.
                u8 ip_ofs;
                u8 csum_ofs;
                u8 csum_start = 0;
                u16 partial_csum = 0;
                bool udp = reg_num;
                u32 pkt_len = ctx->mem.named.tx_buf_offset;
                if (opcode != ALLOC_XMIT_OPCODE) {
                    // parse TRANSMIT_EXT_OPCODE arguments
                    ip_ofs = DECODE_U8();                 // 2nd imm, at worst 5 B past prog_len
                    csum_ofs = DECODE_U8();               // 3rd imm, at worst 6 B past prog_len
                    if (csum_ofs < 255) {
                        csum_start = DECODE_U8();         // 4th imm, at worst 7 B past prog_len
                        partial_csum = decode_be16(ctx);  // 5th imm, at worst 9 B past prog_len
                    }
                } else if (imm_len) {
                    // parse ALLOC_XMIT_OPCODE (R=0) immediate
                    static const u8 auto_csum_start[8] = { 26, 26, 34, 38, 22, 22, 22, 22 };
                    static const u8 auto_csum_ofs[8] =   { 40, 44, 36, 40, 60, 64, 56, 64 };
                    ip_ofs = 14;
                    csum_ofs = auto_csum_ofs[imm & 7];
                    csum_start = auto_csum_start[imm & 7];
                    partial_csum = imm >> 3;
                    udp = !(imm & 3);
                } else {
                    // ALLOC_XMIT_OPCODE (R=0) with no immediate
                    ip_ofs = csum_ofs = 255;
                }
                ASSERT_RETURN(ctx->tx_buf);
                // If pkt_len > allocate_buffer_len, it means sth. wrong
                // happened and the tx_buf should be deallocated.
                if (pkt_len > ctx->tx_buf_len) {
                    do_discard_buffer(ctx);
                    return EXCEPTION;
                }
                {
                    int dscp = csum_and_return_dscp(ctx->tx_buf, (s32)pkt_len, ip_ofs,
                                                    partial_csum, csum_start, csum_ofs, udp);
                    int ret = do_transmit_buffer(ctx, pkt_len, dscp);
                    if (ret) { counter[-4]++; return EXCEPTION; } // transmit failure
                }
                break;
              }
              case EPKTDATACOPYIMM_EXT_OPCODE:  // 41
              case EPKTDATACOPYR1_EXT_OPCODE:   // 42
                pktcopy_src_offset = ctx->R[0];
                FALLTHROUGH;
              case PKTDATACOPYIMM_EXT_OPCODE: { // 65536
                u32 dst_offs = ctx->mem.named.tx_buf_offset;
                u32 copy_len = ctx->R[1];
                if (imm != EPKTDATACOPYR1_EXT_OPCODE) {
                    copy_len = DECODE_U8();  // 2nd imm, at worst 8 bytes past prog_len
                    if (!copy_len) copy_len = 256 + DECODE_U8(); // at worst 9 bytes past prog_len
                }
                ASSERT_RETURN(ctx->tx_buf);
                ASSERT_IN_OUTPUT_BOUNDS(dst_offs, copy_len);
                if (reg_num == 0) {  // copy from packet
                    const u32 last_packet_offs = pktcopy_src_offset + copy_len - 1;
                    ASSERT_IN_PACKET_BOUNDS(pktcopy_src_offset);
                    ASSERT_RETURN(last_packet_offs >= pktcopy_src_offset);
                    ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
                    memcpy(ctx->tx_buf + dst_offs, ctx->packet + pktcopy_src_offset, copy_len);
                } else {  // copy from data
                    ASSERT_IN_RAM_BOUNDS(pktcopy_src_offset + copy_len - 1);
                    memcpy(ctx->tx_buf + dst_offs, ctx->program + pktcopy_src_offset, copy_len);
                }
                dst_offs += copy_len;
                ctx->mem.named.tx_buf_offset = dst_offs;
                break;
              }
              case JDNSQMATCH_EXT_OPCODE:        // 43 - 43 =  0 = 0b0000, u8
              case JDNSAMATCH_EXT_OPCODE:        // 44 - 43 =  1 = 0b0001,
              case JDNSQMATCHSAFE_EXT_OPCODE:    // 45 - 43 =  2 = 0b0010, u8
              case JDNSAMATCHSAFE_EXT_OPCODE:    // 46 - 43 =  3 = 0b0011,
              case JDNSQMATCH2_EXT_OPCODE:       // 51 - 43 =  8 = 0b1000, u8 u8
              case JDNSQMATCHSAFE2_EXT_OPCODE:   // 53 - 43 = 10 = 0b1010, u8 u8
              case JDNSQMATCH1_EXT_OPCODE:       // 55 - 43 = 12 = 0b1100, u16
              case JDNSQMATCHSAFE1_EXT_OPCODE: { // 57 - 43 = 14 = 0b1110, u16
                u32 jump_offs = decode_imm(ctx, imm_len); // 2nd imm, at worst 8 B past prog_len
                int qtype1 = -1;
                int qtype2;
                imm -= JDNSQMATCH_EXT_OPCODE;  // Correction for easier opcode handling
                // Now, we have:
                //   imm & 1 --> no following u8
                //   imm & 2 --> 'SAFE'
                //   imm & 4 --> join two u8s into a be16
                //   imm & 8 --> second u8
                // bit 0 clear means we need to parse a u8, set means 'A' opcode variety
                if (!(imm & 1)) qtype1 = DECODE_U8();  // 3rd imm, at worst 9 bytes past prog_len
                // bit 3 set means we need to parse another u8
                if (imm & 8) {
                    qtype2 = DECODE_U8();  // 4th imm, at worst 10 bytes past prog_len
                } else {
                    qtype2 = qtype1;
                }
                // bit 2 set means we need to join the two u8s into a be16
                if (imm & 4) qtype2 = qtype1 = (qtype1 << 8) | qtype2;
                {
                    u32 udp_payload_offset = ctx->R[0];
                    match_result_type match_rst = match_names(ctx->program + ctx->pc,
                                                              ctx->program + ctx->program_len,
                                                              ctx->packet + udp_payload_offset,
                                                              ctx->packet_len - udp_payload_offset,
                                                              qtype1,
                                                              qtype2);
                    if (match_rst == error_program) return EXCEPTION;
                    if (match_rst == error_packet) {
                        counter[-5]++; // increment error dns packet counter
                        return (imm & 2) ? PASS : DROP;  // imm & 2 detects SAFE opcodes
                    }
                    while (ctx->pc + 1 < ctx->program_len &&
                           (ctx->program[ctx->pc] || ctx->program[ctx->pc + 1])) {
                        ctx->pc++;
                    }
                    ctx->pc += 2;  // skip the final double 0 needle end
                    // relies on reg_num in {0,1} and match_rst being {false=0, true=1}
                    if (!(reg_num ^ (u32)match_rst)) ctx->pc += jump_offs;
                }
                break;
              }
              case EWRITE1_EXT_OPCODE:
              case EWRITE2_EXT_OPCODE:
              case EWRITE4_EXT_OPCODE: {
                const u32 write_len = 1 << (imm - EWRITE1_EXT_OPCODE);
                ASSERT_RETURN(ctx->tx_buf);
                ASSERT_IN_OUTPUT_BOUNDS(ctx->mem.named.tx_buf_offset, write_len);
                for (u32 i = 0; i < write_len; ++i) {
                    ctx->tx_buf[ctx->mem.named.tx_buf_offset++] =
                        (u8)(REG >> (write_len - 1 - i) * 8);
                }
                break;
              }
              case JONEOF_EXT_OPCODE: {
                u32 jump_offs = decode_imm(ctx, imm_len); // 2nd imm, at worst 8 B past prog_len
                u8 imm3 = DECODE_U8();  // 3rd imm, at worst 9 bytes past prog_len
                bool jmp = imm3 & 1;  // =0 jmp on match, =1 jmp on no match
                u8 len = ((imm3 >> 1) & 3) + 1;  // size [1..4] in bytes of an element
                u8 cnt = (imm3 >> 3) + 2;  // number [2..33] of elements in set
                if (ctx->pc + cnt * len > ctx->program_len) return EXCEPTION;
                // cnt underflow on final iteration not an issue as not used after loop.
                while (cnt--) {
                    u32 v = 0;
                    for (int i = 0; i < len; ++i) v = (v << 8) | DECODE_U8();
                    if (REG == v) jmp ^= true;
                }
                if (jmp) ctx->pc += jump_offs;
                break;
              }
              case EXCEPTIONBUFFER_EXT_OPCODE: {
                ctx->except_buf_sz = decode_be16(ctx);
                break;
              }
              default:  // Unknown extended opcode
                return EXCEPTION;  // Bail out
            }
            break;
          case LDDW_OPCODE:
          case STDW_OPCODE:
            if (ctx->v6) {
                if (!imm) return EXCEPTION;
                if (imm > 0xFFFF) return EXCEPTION;
                if (imm * 4 > ctx->ram_len) return EXCEPTION;
                if (opcode == LDDW_OPCODE) {
                    REG = counter[-(s32)imm];
                } else {
                    counter[-(s32)imm] = REG;
                }
            } else {
                u32 size = 4;
                u32 offs = OTHER_REG + (u32)signed_imm;
                // Negative offsets wrap around the end of the address space.
                // This allows us to efficiently access the end of the
                // address space with one-byte immediates without using %=.
                if (offs & 0x80000000) offs += ctx->ram_len;  // unsigned overflow intended
                ASSERT_IN_DATA_BOUNDS(offs, size);
                if (opcode == LDDW_OPCODE) {
                    u32 val = 0;
                    // size underflow on final iteration not an issue as not used after loop.
                    while (size--) val = (val << 8) | ctx->program[offs++];
                    REG = val;
                } else {
                    u32 val = REG;
                    // size underflow on final iteration not an issue as not used after loop.
                    while (size--) {
                        ctx->program[offs++] = (val >> 24);
                        val <<= 8;
                    }
                }
            }
            break;
          case WRITE_OPCODE: {
            ASSERT_RETURN(ctx->tx_buf);
            ASSERT_RETURN(len_field);
            const u32 write_len = 1 << (len_field - 1);
            ASSERT_IN_OUTPUT_BOUNDS(ctx->mem.named.tx_buf_offset, write_len);
            for (u32 i = 0; i < write_len; ++i) {
                ctx->tx_buf[ctx->mem.named.tx_buf_offset++] =
                    (u8)(imm >> (write_len - 1 - i) * 8);
            }
            break;
          }
          case ALLOC_XMIT_OPCODE:
            if (reg_num) goto do_allocate; else goto do_transmit;
            break;
          default:  // Unknown opcode
            return EXCEPTION;  // Bail out
        }
      }
    // instructions_remaining underflow on final iteration not an issue as not used after loop.
    } while (instructions_remaining--);
    return EXCEPTION;
}

static int apf_runner(struct apf_fw_ctx *ctx, u32 *const program, const u32 program_len,
                      const u32 ram_len, const u8 *const packet,
                      const u32 packet_len, const u32 filter_age_16384ths) {
    // Due to direct 32-bit read/write access to counters at end of ram
    // APFv6 interpreter requires program & ram_len to be 4 byte aligned.
    if (3 & (uintptr_t)program) return EXCEPTION;
    if (3 & ram_len) return EXCEPTION;
    if (ram_len < 1024) return EXCEPTION; // due to JBSPTR

    // We rely on ram_len + 65536 not overflowing, so require ram_len < 2GiB
    // Similarly LDDW/STDW have special meaning for negative ram offsets.
    // We also don't want garbage like program_len == 0xFFFFFFFF
    if ((program_len | ram_len) >> 31) return EXCEPTION;

    {
        apf_context apf_ctx = {
            .ptr_size = (u8)sizeof(void*),
            .caller_ctx = ctx,
            .program = (u8*)program,
            .program_len = program_len,
            .ram_len = ram_len,
            .packet = packet,
            .packet_len = packet_len,
            .mem.named = {
                .program_size = program_len,
                .ram_len = ram_len,
                .packet_size = packet_len,
                .apf_version = APF_VERSION,
                .filter_age = filter_age_16384ths >> 14,
                .filter_age_16384ths = filter_age_16384ths,
                .internal_state = 0 // TODO: use proper value
            }
        };

        int ret = do_apf_run(&apf_ctx);
        if (apf_ctx.tx_buf) do_discard_buffer(&apf_ctx);
        // Convert any exceptions internal to the program to just normal 'PASS'
        if (ret >= EXCEPTION) {
            u16 buf_size = apf_ctx.except_buf_sz;
            if (buf_size >= sizeof(apf_ctx) && apf_ctx.program_len + buf_size <= apf_ctx.ram_len) {
                u8* buf = apf_ctx.program + apf_ctx.program_len;
                memcpy(buf, &apf_ctx, sizeof(apf_ctx));
                buf_size -= sizeof(apf_ctx);
                buf += sizeof(apf_ctx);
                if (buf_size > apf_ctx.packet_len) buf_size = apf_ctx.packet_len;
                memcpy(buf, apf_ctx.packet, buf_size);
            }
            ret = PASS;
        }
        return ret;
    }
}

int apf_run(struct apf_fw_ctx *ctx, u32 *const program, const u32 program_len,
            const u32 ram_len, const u8 *const packet,
            const u32 packet_len, const u32 filter_age_16384ths) {
    // Any valid ethernet packet should be at least ETH_HLEN long...
    if (!packet) return EXCEPTION;
    if (packet_len < ETH_HLEN) return EXCEPTION;

    return apf_runner(ctx, program, program_len, ram_len, packet, packet_len, filter_age_16384ths);
}
FOR_KERNEL(apf_run)
