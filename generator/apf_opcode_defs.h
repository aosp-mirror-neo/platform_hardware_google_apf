/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef APF_OPCODE_DEFS_H
#define APF_OPCODE_DEFS_H

/*
 * Memory slot definitions and standard/extended opcodes below are copied from
 * apf.h / apf_interpreter.c so that host-side generator implementation and
 * firmware interpreter definitions stay in sync.
 *
 * Number of temporary memory slots, see ldm/stm instructions.
 */
#define MEMORY_ITEMS 16
/* Upon program execution, some temporary memory slots are prefilled: */
#define MEMORY_OFFSET_INTERNAL_STATE      7   /* Internal state bitmask */
#define MEMORY_OFFSET_APF_VERSION         8   /* Initialized with apf_version() */
#define MEMORY_OFFSET_FILTER_AGE_16384THS 9   /* Filter age in 1/16384 seconds */
#define MEMORY_OFFSET_TX_BUF_OFFSET       10  /* Offset in tx_buf for next write */
#define MEMORY_OFFSET_PROGRAM_SIZE        11  /* Size of program (in bytes) */
#define MEMORY_OFFSET_DATA_SIZE           12  /* Total size of program + data (ram_len) */
#define MEMORY_OFFSET_IPV4_HEADER_SIZE    13  /* 4*([ETH_HLEN]&15) */
#define MEMORY_OFFSET_PACKET_SIZE         14  /* Size of packet in bytes */
#define MEMORY_OFFSET_FILTER_AGE          15  /* Age since filter installed in seconds */

/* ---------------------------------------------------------------------------------------------- */

/* Standard opcodes (copied from apf.h / apf_interpreter.c). */

/* Unconditionally pass (if R=0) or drop (if R=1) packet and optionally increment counter.
 * An optional non-zero unsigned immediate value can be provided to encode the counter number.
 * The counter is located (-4 * counter number) bytes from the end of the data region.
 * It is a U32 big-endian value and is always incremented by 1.
 * This is more or less equivalent to: lddw R0, -4*N; add R0, 1; stdw R0, -4*N; {pass,drop}
 * e.g. "pass", "pass 1", "drop", "drop 1"
 */
#define PASSDROP_OPCODE 0

#define LDB_OPCODE 1    /* Load 1 byte  from immediate offset, e.g. "ldb R0, [5]" */
#define LDH_OPCODE 2    /* Load 2 bytes from immediate offset, e.g. "ldh R0, [5]" */
#define LDW_OPCODE 3    /* Load 4 bytes from immediate offset, e.g. "ldw R0, [5]" */
#define LDBX_OPCODE 4   /* Load 1 byte  from immediate offset plus register, e.g. "ldbx R0, [5+R1]" */
#define LDHX_OPCODE 5   /* Load 2 bytes from immediate offset plus register, e.g. "ldhx R0, [5+R1]" */
#define LDWX_OPCODE 6   /* Load 4 bytes from immediate offset plus register, e.g. "ldwx R0, [5+R1]" */
#define ADD_OPCODE 7    /* Add, e.g. "add R0,5" */
#define MUL_OPCODE 8    /* Multiply, e.g. "mul R0,5" */
#define DIV_OPCODE 9    /* Divide, e.g. "div R0,5" */
#define AND_OPCODE 10   /* And, e.g. "and R0,5" */
#define OR_OPCODE 11    /* Or, e.g. "or R0,5" */
#define SH_OPCODE 12    /* Left shift, e.g. "sh R0, 5" or "sh R0, -5" (shifts right) */
#define LI_OPCODE 13    /* Load signed immediate, e.g. "li R0,5" */
#define JMP_OPCODE 14   /* Unconditional jump, e.g. "jmp label" */
#define JEQ_OPCODE 15   /* Compare equal and branch, e.g. "jeq R0,5,label" */
#define JNE_OPCODE 16   /* Compare not equal and branch, e.g. "jne R0,5,label" */
#define JGT_OPCODE 17   /* Compare greater than and branch, e.g. "jgt R0,5,label" */
#define JLT_OPCODE 18   /* Compare less than and branch, e.g. "jlt R0,5,label" */
#define JSET_OPCODE 19  /* Compare any bits set and branch, e.g. "jset R0,5,label" */
#define JBSMATCH_OPCODE 20 /* Compare byte sequence [R=0 not] equal, e.g. "jbsne R0,2,label,0x1122" */
                           /* NOTE: Only APFv6+ implements R=1 'jbseq' version and multi match */
                           /* imm1 is jmp target, imm2 is (cnt - 1) * 2048 + compare_len, */
                           /* which is followed by cnt * compare_len bytes to compare against. */
                           /* Warning: do not specify the same byte sequence multiple times. */
#define EXT_OPCODE 21   /* Immediate value is one of *_EXT_OPCODE */
#define LDDW_OPCODE 22  /* Load 4 bytes from data address (register + signed imm): "lddw R0, [5+R1]" */
                        /* LDDW/STDW in APFv6+ *mode* load/store from counter specified in imm. */
#define STDW_OPCODE 23  /* Store 4 bytes to data address (register + signed imm): "stdw R0, [5+R1]" */

/* Write 1, 2 or 4 byte immediate to the output buffer and auto-increment the output buffer pointer.
 * Immediate length field specifies size of write.  R must be 0.  imm_len != 0.
 * e.g. "write 5"
 */
#define WRITE_OPCODE 24

/* Copy bytes from input packet/APF program/data region to output buffer and
 * auto-increment the output buffer pointer.
 * Register bit is used to specify the source of data copy.
 * R=0 means copy from packet.
 * R=1 means copy from APF program/data region.
 * The source offset is stored in imm1, copy length is stored in u8 imm2.
 * APFv6.1: if u8 imm2 is 0 then copy length is 256 + extra u8 imm3
 * e.g. "pktcopy 0, 16" or "datacopy 0, 16"
 */
#define PKTDATACOPY_OPCODE 25

#define JNSET_OPCODE 26 /* JSET with reverse condition (jump if no bits set) */

/* APFv6.1: Compare byte sequence [R=0 not] equal, e.g. "jbsptrne 22,16,label,<dataptr>"
 * imm1 is jmp target
 * imm2(u8) is offset [0..255] into packet
 * imm3(u8) is (count - 1) * 16 + (compare_len - 1), thus both count & compare_len are in [1..16]
 * which is followed by count u8 'even offset' ptrs into max 526 byte data section to compare
 * against - ie. they are multiplied by 2 and have 3 added to them (to skip over 'datajmp u16')
 * Warning: do not specify the same byte sequence multiple times.
 */
#define JBSPTRMATCH_OPCODE 27

/* APFv6.1: Bytecode optimized allocate | transmit instruction.
 * R=1 -> allocate(266 + imm * 8)
 * R=0 -> transmit
 *   immlen=0 -> no checksum offload (transmit ip_ofs=255)
 *   immlen>0 -> with checksum offload (transmit(udp) ip_ofs=14 ...)
 *     imm & 7 | type of offload      | ip_ofs | udp | csum_start  | csum_ofs      | partial_csum |
 *         0   | ip4/udp              |   14   |  X  | 14+20-8 =26 | 14+20   +6=40 |   imm >> 3   |
 *         1   | ip4/tcp              |   14   |     | 14+20-8 =26 | 14+20  +10=44 |     --"--    |
 *         2   | ip4/icmp             |   14   |     | 14+20   =34 | 14+20   +2=36 |     --"--    |
 *         3   | ip4/routeralert/icmp |   14   |     | 14+20+4 =38 | 14+20+4 +2=40 |     --"--    |
 *         4   | ip6/udp              |   14   |  X  | 14+40-32=22 | 14+40   +6=60 |     --"--    |
 *         5   | ip6/tcp              |   14   |     | 14+40-32=22 | 14+40  +10=64 |     --"--    |
 *         6   | ip6/icmp             |   14   |     | 14+40-32=22 | 14+40   +2=56 |     --"--    |
 *         7   | ip6/routeralert/icmp |   14   |     | 14+40-32=22 | 14+40+8 +2=64 |     --"--    |
 *   Note: +10=44/64 for types 1/5 is an APFv6.1 bug (TCP csum is +16=50/70), fixed in APFvNEXT.
 */
#define ALLOC_XMIT_OPCODE 28

/* Extended opcodes (copied from apf.h / apf_interpreter.c).
 * These all have an opcode of EXT_OPCODE and specify the actual opcode in the immediate field.
 */
#define LDM_EXT_OPCODE 0   /* Load from temporary memory, e.g. "ldm R0,5" */
  /* Values 0-15 represent loading the different temporary memory slots. */
#define STM_EXT_OPCODE 16  /* Store to temporary memory, e.g. "stm R0,5" */
  /* Values 16-31 represent storing to the different temporary memory slots. */
#define NOT_EXT_OPCODE 32  /* Not, e.g. "not R0" */
#define NEG_EXT_OPCODE 33  /* Negate, e.g. "neg R0" */
#define SWAP_EXT_OPCODE 34 /* Swap, e.g. "swap R0,R1" */
#define MOV_EXT_OPCODE 35  /* Move, e.g. "move R0,R1" */

/* Allocate writable output buffer.
 * R=0: register R0 specifies the length
 * R=1: length provided in u16 imm2
 * e.g. "allocate R0" or "allocate 123"
 * On failure automatically executes 'pass 3'
 */
#define ALLOCATE_EXT_OPCODE 36

/* Transmit and deallocate the buffer (transmission can be delayed until the program
 * terminates).  Length of buffer is the output buffer pointer (0 means discard).
 * R=1 iff udp style L4 checksum
 * u8 imm2 - ip header offset from start of buffer (255 for non-ip packets)
 * u8 imm3 - offset from start of buffer to store L4 checksum (255 for no L4 checksum)
 * u8 imm4 - offset from start of buffer to begin L4 checksum calculation (present iff imm3 != 255)
 * u16 imm5 - partial checksum value to include in L4 checksum (present iff imm3 != 255)
 * e.g. "transmit"
 */
#define TRANSMIT_EXT_OPCODE 37

/* Write 1, 2 or 4 byte value from register to the output buffer and auto-increment the
 * output buffer pointer.
 * e.g. "ewrite1 r0" or "ewrite2 r1"
 */
#define EWRITE1_EXT_OPCODE 38
#define EWRITE2_EXT_OPCODE 39
#define EWRITE4_EXT_OPCODE 40

/* Copy bytes from input packet/APF program/data region to output buffer and
 * auto-increment the output buffer pointer.
 * Register bit is used to specify the source of data copy.
 * R=0 means copy from packet.
 * R=1 means copy from APF program/data region.
 * The source offset is stored in R0, copy length is stored in u8 imm2 or R1.
 * APFv6.1: if u8 imm2 is 0 then copy length is 256 + extra u8 imm3.
 * e.g. "epktcopy r0, 16", "edatacopy r0, 16", "epktcopy r0, r1", "edatacopy r0, r1"
 */
#define EPKTDATACOPYIMM_EXT_OPCODE 41
#define EPKTDATACOPYR1_EXT_OPCODE 42

/* Jumps if the UDP payload content (starting at R0) does [not] match one
 * of the specified QNAMEs in question records, applying case insensitivity.
 * SAFE version PASSES corrupt packets, while the other one DROPS.
 * R=0/1 meaning 'does not match'/'matches'
 * R0: Offset to UDP payload content
 * imm1: Extended opcode
 * imm2: Jump label offset
 * imm3(u8): Question type (PTR/SRV/TXT/A/AAAA)
 *   note: imm3 is instead u16 in '1' version
 * imm4(bytes): null terminated list of null terminated LV-encoded QNAMEs
 * e.g.: "jdnsqeq R0,label,0xc,\002aa\005local\0\0", "jdnsqne R0,label,0xc,\002aa\005local\0\0"
 */
#define JDNSQMATCH_EXT_OPCODE 43
#define JDNSQMATCHSAFE_EXT_OPCODE 45
#define JDNSQMATCH1_EXT_OPCODE 55
#define JDNSQMATCHSAFE1_EXT_OPCODE 57

/* Jumps if the UDP payload content (starting at R0) does [not] match one
 * of the specified NAMEs in answers/authority/additional records, applying
 * case insensitivity.
 * SAFE version PASSES corrupt packets, while the other one DROPS.
 * R=0/1 meaning 'does not match'/'matches'
 * R0: Offset to UDP payload content
 * imm1: Extended opcode
 * imm2: Jump label offset
 * imm3(bytes): null terminated list of null terminated LV-encoded NAMEs
 * e.g.: "jdnsaeq R0,label,\002aa\005local\0\0", "jdnsane R0,label,\002aa\005local\0\0"
 */
#define JDNSAMATCH_EXT_OPCODE 44
#define JDNSAMATCHSAFE_EXT_OPCODE 46

/* Jumps if the UDP payload content (starting at R0) does [not] match one
 * of the specified QNAMEs in question records, applying case insensitivity.
 * The qtypes in the input packet can match either of the two supplied qtypes.
 * SAFE version PASSES corrupt packets, while the other one DROPS.
 * R=0/1 meaning 'does not match'/'matches'
 * R0: Offset to UDP payload content
 * imm1: Extended opcode
 * imm2: Jump label offset
 * imm3(u8): Question type1 (PTR/SRV/TXT/A/AAAA)
 * imm4(u8): Question type2 (PTR/SRV/TXT/A/AAAA)
 * imm5(bytes): null terminated list of null terminated LV-encoded QNAMEs
 * e.g.: "jdnsqeq2 R0,label,A,AAAA,\002aa\005local\0\0",
 *       "jdnsqne2 R0,label,A,AAAA,\002aa\005local\0\0"
 */
#define JDNSQMATCH2_EXT_OPCODE 51
#define JDNSQMATCHSAFE2_EXT_OPCODE 53

/* Jump if register is [not] one of the list of values
 * R bit - specifies the register (R0/R1) to test
 * imm1: Extended opcode
 * imm2: Jump label offset
 * imm3(u8): top 5 bits - number 'n' of following u8/be16/be32 values - 2
 *        middle 2 bits - 1..4 length of immediates - 1
 *        bottom 1 bit  - =0 jmp if in set, =1 if not in set
 * imm4(n * 1/2/3/4 bytes): the *UNIQUE* values to compare against
 */
#define JONEOF_EXT_OPCODE 47

/* Specify length of exception buffer, which is populated on abnormal program termination.
 * imm1: Extended opcode
 * imm2(u16): Length of exception buffer (located *immediately* after the program itself)
 */
#define EXCEPTIONBUFFER_EXT_OPCODE 48

#endif /* APF_OPCODE_DEFS_H */
