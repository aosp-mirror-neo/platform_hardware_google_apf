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

#include "apf_interpreter.h"

#include <string.h>  // For memcmp, memcpy, memset

#if __GNUC__ >= 7 || __clang__
#define FALLTHROUGH __attribute__((fallthrough))
#else
#define FALLTHROUGH
#endif

#undef bool
#undef true
#undef false
typedef enum { False, True } Boolean;
#define bool Boolean
#define true True
#define false False

#include "apf_defs.h"
#include "apf.h"
#include "apf_utils.h"
#include "apf_dns.h"
#include "apf_checksum.h"

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

u32 apf_version(void) {
    return 20250228;
}

typedef struct {
    // Note: the following 4 fields take up exactly 8 bytes.
    u16 except_buf_sz; // Length of the exception buffer (at program_len offset)
    u8 ptr_size;       // sizeof(void*)
    u8 v6;             // Set to 1 by first jmpdata (APFv6+) instruction
    u32 pc;            // Program counter.
    // All the pointers should be next to each other for better struct packing.
    // We are at offset 8, so even 64-bit pointers will not need extra padding.
    void *caller_ctx;  // Passed in to interpreter, passed through to alloc/transmit.
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

FUNC(int do_transmit_buffer(apf_context* ctx, u32 pkt_len, u8 dscp)) {
    int ret = apf_transmit_buffer(ctx->caller_ctx, ctx->tx_buf, pkt_len, dscp);
    ctx->tx_buf = NULL;
    ctx->tx_buf_len = 0;
    return ret;
}

static int do_discard_buffer(apf_context* ctx) {
    return do_transmit_buffer(ctx, 0 /* pkt_len */, 0 /* dscp */);
}

#define DECODE_U8() (ctx->program[ctx->pc++])

static u16 decode_be16(apf_context* ctx) {
    u16 v = DECODE_U8();
    v <<= 8;
    v |= DECODE_U8();
    return v;
}

// Decode an immediate, lengths [0..4] all work, does not do range checking.
// But note that program is at least 20 bytes shorter than ram, so first few
// immediates can always be safely decoded without exceeding ram buffer.
static u32 decode_imm(apf_context* ctx, u32 length) {
    u32 i, v = 0;
    for (i = 0; i < length; ++i) v = (v << 8) | DECODE_U8();
    return v;
}

// Warning: 'ofs' should be validated by caller!
static u8 read_packet_u8(apf_context* ctx, u32 ofs) {
    return ctx->packet[ofs];
}

static int do_apf_run(apf_context* ctx) {
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

    // APFv6 requires at least 5 u32 counters at the end of ram, this makes counter[-5]++ valid
    // This cannot wrap due to previous check, that enforced program_len & ram_len < 2GiB.
    if (ctx->program_len + 20 > ctx->ram_len) return EXCEPTION;

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
            {
                const u32 end_offs = offs + (load_size - 1);
                u32 val = 0;
                // Catch overflow/wrap-around.
                ASSERT_RETURN(end_offs >= offs);
                ASSERT_IN_PACKET_BOUNDS(end_offs);
                // load_size underflow on final iteration not an issue as not used after loop.
                while (load_size--) val = (val << 8) | read_packet_u8(ctx, offs++);
                REG = val;
            }
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
                ASSERT_RETURN(ctx->tx_buf == NULL);
                if (reg_num == 0) {
                    ctx->tx_buf_len = REG;
                } else {
                    ctx->tx_buf_len = decode_be16(ctx); // 2nd imm, at worst 6 B past prog_len
                }
                // checksumming functions requires minimum 266 byte buffer for correctness
                if (ctx->tx_buf_len < 266) ctx->tx_buf_len = 266;
                ctx->tx_buf = apf_allocate_buffer(ctx->caller_ctx, ctx->tx_buf_len);
                if (!ctx->tx_buf) {  // allocate failure
                    ctx->tx_buf_len = 0;
                    counter[-3]++;
                    return EXCEPTION;
                }
                memset(ctx->tx_buf, 0, ctx->tx_buf_len);
                ctx->mem.named.tx_buf_offset = 0;
                break;
              case TRANSMIT_EXT_OPCODE: {
                // tx_buf_len cannot be large because we'd run out of RAM,
                // so the above unsigned comparison effectively guarantees casting pkt_len
                // to a signed value does not result in it going negative.
                u8 ip_ofs = DECODE_U8();              // 2nd imm, at worst 5 B past prog_len
                u8 csum_ofs = DECODE_U8();            // 3rd imm, at worst 6 B past prog_len
                u8 csum_start = 0;
                u16 partial_csum = 0;
                u32 pkt_len = ctx->mem.named.tx_buf_offset;
                ASSERT_RETURN(ctx->tx_buf);
                // If pkt_len > allocate_buffer_len, it means sth. wrong
                // happened and the tx_buf should be deallocated.
                if (pkt_len > ctx->tx_buf_len) {
                    do_discard_buffer(ctx);
                    return EXCEPTION;
                }
                if (csum_ofs < 255) {
                    csum_start = DECODE_U8();         // 4th imm, at worst 7 B past prog_len
                    partial_csum = decode_be16(ctx);  // 5th imm, at worst 9 B past prog_len
                }
                {
                    int dscp = csum_and_return_dscp(ctx->tx_buf, (s32)pkt_len, ip_ofs,
                                                    partial_csum, csum_start, csum_ofs,
                                                    (bool)reg_num);
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
              case JDNSQMATCH_EXT_OPCODE:       // 43
              case JDNSAMATCH_EXT_OPCODE:       // 44
              case JDNSQMATCHSAFE_EXT_OPCODE:   // 45
              case JDNSAMATCHSAFE_EXT_OPCODE: { // 46
                u32 jump_offs = decode_imm(ctx, imm_len); // 2nd imm, at worst 8 B past prog_len
                int qtype = -1;
                if (imm & 1) { // JDNSQMATCH & JDNSQMATCHSAFE are *odd* extended opcodes
                    qtype = DECODE_U8();  // 3rd imm, at worst 9 bytes past prog_len
                }
                {
                    u32 udp_payload_offset = ctx->R[0];
                    match_result_type match_rst = match_names(ctx->program + ctx->pc,
                                                              ctx->program + ctx->program_len,
                                                              ctx->packet + udp_payload_offset,
                                                              ctx->packet_len - udp_payload_offset,
                                                              qtype);
                    if (match_rst == error_program) return EXCEPTION;
                    if (match_rst == error_packet) {
                        counter[-5]++; // increment error dns packet counter
                        return (imm >= JDNSQMATCHSAFE_EXT_OPCODE) ? PASS : DROP;
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
                u32 i;
                ASSERT_RETURN(ctx->tx_buf);
                ASSERT_IN_OUTPUT_BOUNDS(ctx->mem.named.tx_buf_offset, write_len);
                for (i = 0; i < write_len; ++i) {
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
                    int i;
                    for (i = 0; i < len; ++i) v = (v << 8) | DECODE_U8();
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
            {
                const u32 write_len = 1 << (len_field - 1);
                u32 i;
                ASSERT_IN_OUTPUT_BOUNDS(ctx->mem.named.tx_buf_offset, write_len);
                for (i = 0; i < write_len; ++i) {
                    ctx->tx_buf[ctx->mem.named.tx_buf_offset++] =
                        (u8)(imm >> (write_len - 1 - i) * 8);
                }
            }
            break;
          }
          default:  // Unknown opcode
            return EXCEPTION;  // Bail out
        }
      }
    // instructions_remaining underflow on final iteration not an issue as not used after loop.
    } while (instructions_remaining--);
    return EXCEPTION;
}

static int apf_runner(void* ctx, u32* const program, const u32 program_len,
                      const u32 ram_len, const u8* const packet,
                      const u32 packet_len, const u32 filter_age_16384ths) {
    // Due to direct 32-bit read/write access to counters at end of ram
    // APFv6 interpreter requires program & ram_len to be 4 byte aligned.
    if (3 & (uintptr_t)program) return EXCEPTION;
    if (3 & ram_len) return EXCEPTION;

    // We rely on ram_len + 65536 not overflowing, so require ram_len < 2GiB
    // Similarly LDDW/STDW have special meaning for negative ram offsets.
    // We also don't want garbage like program_len == 0xFFFFFFFF
    if ((program_len | ram_len) >> 31) return EXCEPTION;

    {
        apf_context apf_ctx = { 0 };
        int ret;

        apf_ctx.ptr_size = sizeof(void*);
        apf_ctx.caller_ctx = ctx;
        apf_ctx.program = (u8*)program;
        apf_ctx.program_len = program_len;
        apf_ctx.ram_len = ram_len;
        apf_ctx.packet = packet;
        apf_ctx.packet_len = packet_len;
        // Fill in pre-filled memory slot values.
        apf_ctx.mem.named.program_size = program_len;
        apf_ctx.mem.named.ram_len = ram_len;
        apf_ctx.mem.named.packet_size = packet_len;
        apf_ctx.mem.named.apf_version = apf_version();
        apf_ctx.mem.named.filter_age = filter_age_16384ths >> 14;
        apf_ctx.mem.named.filter_age_16384ths = filter_age_16384ths;

        ret = do_apf_run(&apf_ctx);
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

int apf_run(void* ctx, u32* const program, const u32 program_len,
            const u32 ram_len, const u8* const packet,
            const u32 packet_len, const u32 filter_age_16384ths) {
    // Any valid ethernet packet should be at least ETH_HLEN long...
    if (!packet) return EXCEPTION;
    if (packet_len < ETH_HLEN) return EXCEPTION;

    return apf_runner(ctx, program, program_len, ram_len, packet, packet_len, filter_age_16384ths);
}
