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

#include "apf_generator.h"

#include <gtest/gtest.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <memory>
#include <string>
#include <vector>

#include "disassembler.h"

namespace {

constexpr uint32_t kDefaultRamLen = 4096;

struct ApfGeneratorDeleter {
    void operator()(struct apf_generator *gen) const { apf_generator_free(gen); }
};

struct FreeDeleter {
    void operator()(void *ptr) const { free(ptr); }
};

using UniqueApfGenerator = std::unique_ptr<struct apf_generator, ApfGeneratorDeleter>;
using UniqueByteBuf = std::unique_ptr<uint8_t, FreeDeleter>;

UniqueApfGenerator AllocGen(uint32_t version = APF_VERSION_61,
                            uint32_t ram_len = kDefaultRamLen) {
    return UniqueApfGenerator(apf_generator_alloc(version, ram_len));
}

UniqueByteBuf GenerateProgram(struct apf_generator *gen, size_t *out_len) {
    if (!out_len) {
        return nullptr;
    }
    size_t req_len = 0;
    if (apf_gen_generate(gen, nullptr, 0, &req_len) != 0) {
        *out_len = 0;
        return nullptr;
    }
    UniqueByteBuf buf(static_cast<uint8_t *>(malloc(req_len > 0 ? req_len : 1)));
    if (!buf) {
        *out_len = 0;
        return nullptr;
    }
    if (apf_gen_generate(gen, buf.get(), req_len, out_len) != 0) {
        return nullptr;
    }
    EXPECT_EQ(*out_len, req_len);
    return buf;
}

std::string Trim(const std::string &s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::vector<std::string> DisassembleProgram(const uint8_t *prog, size_t len) {
    std::vector<std::string> lines;
    for (uint32_t pc = 0; pc < len;) {
        const disas_ret ret =
            apf_disassemble(prog, static_cast<uint32_t>(len), &pc, true /* is_v6 */);
        lines.push_back(Trim(ret.content));
    }
    return lines;
}

uint8_t HexNibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0;
}

std::vector<uint8_t> HexToBytes(const char *hex) {
    std::vector<uint8_t> out;
    size_t len = strlen(hex);
    out.reserve(len / 2);
    for (size_t i = 0; i + 1 < len; i += 2) {
        out.push_back(static_cast<uint8_t>((HexNibble(hex[i]) << 4) | HexNibble(hex[i + 1])));
    }
    return out;
}

int AddJbsneHex(struct apf_generator *gen, apf_label tgt_label, const char *hex) {
    std::vector<uint8_t> bytes = HexToBytes(hex);
    return apf_gen_add_jbsne(gen, tgt_label, bytes.data(), static_cast<uint16_t>(bytes.size()));
}

}  // namespace

TEST(ApfGeneratorTest, testApfInstructions) {
    // Freshly allocated program auto-emits 3-byte empty jmpdata + 4-byte debugbuf prologue
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        size_t len = 999;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 7u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{"0: data        0,", "3: debugbuf    size=4065"}));
    }

    // Test pass opcode: opcode=0 (PASSDROP), imm_len=0, R=0 -> 0x00
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_pass(gen.get());
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 8u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4064",
                      "7: pass",
                  }));
    }

    // Test jumping to pass label (target offset = 0): opcode=14 (JMP), imm_len=0, R=0 -> 0x70
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_jmp(gen.get(), APF_LABEL_PASS);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 8u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4064",
                      "7: jmp         PASS",
                  }));
    }

    // Test jumping to drop label (target offset = 1): opcode=14 (JMP), imm_len=1, R=0, imm=1
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_jmp(gen.get(), APF_LABEL_DROP);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 9u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4063",
                      "7: jmp         DROP",
                  }));
    }

    // Test drop opcode: opcode=0 (PASSDROP), imm_len=0, R=1 -> 0x01
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_drop(gen.get());
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 8u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4064",
                      "7: drop",
                  }));
    }

    // Test jumping if equal to 0: opcode=15 (JEQ), imm_len=1, R=0, target=1, val=0
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_jeq(gen.get(), 0, APF_LABEL_DROP);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 10u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4062",
                      "7: jeq         r0, 0x0, DROP",
                  }));
    }

    // Test jumping if not equal to 0: opcode=16 (JNE), imm_len=1, R=0, target=1, val=0
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_jne(gen.get(), 0, APF_LABEL_DROP);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 10u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4062",
                      "7: jne         r0, 0x0, DROP",
                  }));
    }

    // Test R0 vs R1 branch comparisons (apf_gen_add_j*_r1 emits only target offset)
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_jeq_r1(gen.get(), apf_gen_cnt_drop_label(7));
        apf_gen_add_jne_r1(gen.get(), APF_LABEL_PASS);
        apf_gen_add_jgt_r1(gen.get(), APF_LABEL_DROP);
        apf_gen_add_jlt_r1(gen.get(), APF_LABEL_PASS);
        apf_gen_add_jset_r1(gen.get(), APF_LABEL_DROP);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 17u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4051",
                      "7: jeq         r0, r1, cnt_and_drop[cnt=7]",
                      "9: jne         r0, r1, PASS",
                      "11: jgt         r0, r1, DROP",
                      "13: jlt         r0, r1, PASS",
                      "15: jset        r0, r1, DROP",
                  }));
    }
}

TEST(ApfGeneratorTest, testImmediateEncoding) {
    // 0-byte immediate: li R0, 0
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R0, 0);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 8u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4064",
                      "7: li          r0, 0",
                  }));
    }

    // 1-byte immediate: li R0, 42
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R0, 42);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 9u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4063",
                      "7: li          r0, 42",
                  }));
    }

    // 2-byte immediate: li R1, 0x1234
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R1, 0x1234);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 10u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4062",
                      "7: li          r1, 4660",
                  }));
    }

    // 4-byte immediate: li R0, 0x12345678
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R0, 0x12345678);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 12u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4060",
                      "7: li          r0, 305419896",
                  }));
    }
}

TEST(ApfGeneratorTest, testNegativeImmediateEncoding) {
    // 1-byte negative immediate: li R0, -42
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R0, -42);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 9u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4063",
                      "7: li          r0, -42",
                  }));
    }

    // 2-byte negative immediate: li R1, -0x1122
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R1, -0x1122);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 10u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4062",
                      "7: li          r1, -4386",
                  }));
    }

    // 4-byte negative immediate: li R0, -0x11223344
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R0, -0x11223344);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 12u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4060",
                      "7: li          r0, -287454020",
                  }));
    }
}

TEST(ApfGeneratorTest, testInstructionCountAndProgramLen) {
    auto gen = AllocGen();
    ASSERT_NE(gen, nullptr);
    EXPECT_EQ(apf_gen_get_insn_count(gen.get()), 0u);
    EXPECT_EQ(apf_gen_get_program_len(gen.get()), 7u);

    apf_gen_add_ldb(gen.get(), APF_REG_R0, 5);
    EXPECT_EQ(apf_gen_get_insn_count(gen.get()), 1u);
    EXPECT_EQ(apf_gen_get_program_len(gen.get()), 9u);

    apf_gen_add_jeq(gen.get(), 10, apf_gen_cnt_drop_label(9));
    EXPECT_EQ(apf_gen_get_insn_count(gen.get()), 2u);
    EXPECT_EQ(apf_gen_get_program_len(gen.get()), 12u);

    apf_gen_add_pass(gen.get());
    EXPECT_EQ(apf_gen_get_insn_count(gen.get()), 3u);
    EXPECT_EQ(apf_gen_get_program_len(gen.get()), 13u);

    size_t len = 0;
    auto buf = GenerateProgram(gen.get(), &len);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(len, 13u);
    EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
    EXPECT_EQ(DisassembleProgram(buf.get(), len),
              (std::vector<std::string>{
                  "0: data        0,",
                  "3: debugbuf    size=4047",
                  "7: ldb         r0, [5]",
                  "9: jeq         r0, 0xa, cnt_and_drop[cnt=9]",
                  "12: pass",
              }));
}

TEST(ApfGeneratorTest, testVersionGuards) {
    // Versions prior to APFv6.1 (APFv2, APFv3, APFv4, APFv6.0) MUST be rejected
    EXPECT_EQ(AllocGen(2), nullptr);
    EXPECT_EQ(AllocGen(3), nullptr);
    EXPECT_EQ(AllocGen(4), nullptr);
    EXPECT_EQ(AllocGen(6000), nullptr);

    // APFv6.1+ Generator should allocate successfully
    auto gen_v61 = AllocGen(APF_VERSION_61);
    ASSERT_NE(gen_v61, nullptr);
    apf_gen_add_ldb(gen_v61.get(), APF_REG_R0, 0);
    size_t len = 0;
    auto buf = GenerateProgram(gen_v61.get(), &len);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(DisassembleProgram(buf.get(), len),
              (std::vector<std::string>{
                  "0: data        0,",
                  "3: debugbuf    size=4064",
                  "7: ldb         r0, [0]",
              }));
}

TEST(ApfGeneratorTest, testArithmeticLoadsAndMemoryInstructions) {
    // 1. Test sign-extension protection on AND/ADD/SH (e.g., 0xFF must use 2 bytes 0x00, 0xFF)
    //    and APFv6 arithmetic immediates targeting R1 (R=1, len_field > 0)
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_and(gen.get(), APF_REG_R0, 0xFF);
        apf_gen_add_add(gen.get(), APF_REG_R0, 200);
        apf_gen_add_sh(gen.get(), APF_REG_R0, -4);
        apf_gen_add_and(gen.get(), APF_REG_R0, 0);
        apf_gen_add_add(gen.get(), APF_REG_R1, 10);
        apf_gen_add_mul(gen.get(), APF_REG_R1, 20);
        apf_gen_add_div(gen.get(), APF_REG_R1, 30);
        apf_gen_add_and(gen.get(), APF_REG_R1, -4);
        apf_gen_add_or(gen.get(), APF_REG_R1, 0x80);
        apf_gen_add_sh(gen.get(), APF_REG_R1, 4);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 29u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4043",
                      "7: and         r0, 0xff",
                      "10: add         r0, 200",
                      "13: sh          r0, -4",
                      "15: and         r0, 0x0",
                      "17: add         r1, 10",
                      "19: mul         r1, 20",
                      "21: div         r1, 30",
                      "23: and         r1, 0xfffffffc",
                      "25: or          r1, 0x80",
                      "27: sh          r1, 4",
                  }));
    }

    // 2. Test register-to-register arithmetic (ADD, MUL, DIV, AND, OR, SH with 0-byte immediate)
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_add_reg(gen.get(), APF_REG_R0);
        apf_gen_add_mul_reg(gen.get(), APF_REG_R0);
        apf_gen_add_div_reg(gen.get(), APF_REG_R0);
        apf_gen_add_and_reg(gen.get(), APF_REG_R1);
        apf_gen_add_or_reg(gen.get(), APF_REG_R0);
        apf_gen_add_sh_reg(gen.get(), APF_REG_R0);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 13u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4059",
                      "7: add         r0, r1",
                      "8: mul         r0, r1",
                      "9: div         r0, r1",
                      "10: and         r1, r0",
                      "11: or          r0, r1",
                      "12: sh          r0, r1",
                  }));
    }

    // 3. Test loads, branches, JBSNE/JBSEQ (including max 2047-byte length), LDDW/STDW counters,
    //    and EXT opcodes (LDM, STM, NOT, NEG, SWAP, MOV)
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        const apf_label lbl1 = apf_gen_alloc_label(gen.get());
        const apf_label lbl2 = apf_gen_alloc_label(gen.get());
        const uint8_t oui[4] = {0x50, 0x6F, 0x9A, 0x13};
        const std::vector<uint8_t> max_jbs(2048, 0xAA);
        apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
        apf_gen_add_ldw(gen.get(), APF_REG_R1, 14);
        apf_gen_add_ldbx(gen.get(), APF_REG_R0, 1);
        apf_gen_add_ldhx(gen.get(), APF_REG_R0, 2);
        apf_gen_add_ldwx(gen.get(), APF_REG_R0, 4);
        apf_gen_add_jgt(gen.get(), 100, lbl1);
        apf_gen_add_jlt(gen.get(), 10, lbl1);
        apf_gen_add_jset(gen.get(), 0x01, lbl1);
        apf_gen_add_jbsne(gen.get(), lbl1, oui, sizeof(oui));
        apf_gen_add_jbseq(gen.get(), lbl1, oui, sizeof(oui));
        apf_gen_define_label(gen.get(), lbl1);
        apf_gen_add_jbsne(gen.get(), lbl2, max_jbs.data(), 2047);
        apf_gen_define_label(gen.get(), lbl2);
        apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_PACKET_SIZE);
        apf_gen_add_stm(gen.get(), APF_REG_R0, 0);
        apf_gen_add_not(gen.get(), APF_REG_R0);
        apf_gen_add_neg(gen.get(), APF_REG_R1);
        apf_gen_add_swap(gen.get());
        apf_gen_add_mov(gen.get(), APF_REG_R1);
        apf_gen_add_lddw(gen.get(), APF_REG_R0, 7);
        apf_gen_add_stdw(gen.get(), APF_REG_R0, 7);

        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));

        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=1960",
                      "7: ldh         r0, [12]",
                      "9: ldw         r1, [14]",
                      "11: ldbx        r0, [r1+1]",
                      "13: ldhx        r0, [r1+2]",
                      "15: ldwx        r0, [r1+4]",
                      "17: jgt         r0, 0x64, 40",
                      "20: jlt         r0, 0xa, 40",
                      "23: jset        r0, 0x1, 40",
                      "26: jbsne       r0, (4), 40, 506f9a13",
                      "33: jbseq       r0, (4), 40, 506f9a13",
                      "40: jbsne       r0, (2047), 2092, " + std::string(2047 * 2, 'a'),
                      "2092: ldm         r0, m[14]",
                      "2094: stm         r0, m[0]",
                      "2096: not         r0",
                      "2098: neg         r1",
                      "2100: swap",
                      "2102: mov         r1, r0",
                      "2104: lddw        r0, counter=7",
                      "2106: stdw        counter=7, r0",
                  }));

        // Verify invalid operand cases return -1 and latch sticky error state
        auto err_gen = AllocGen();
        ASSERT_NE(err_gen, nullptr);
        EXPECT_EQ(apf_gen_add_ldh(err_gen.get(), static_cast<enum apf_register>(2), 12), -1);
        EXPECT_EQ(apf_gen_add_jbsne(err_gen.get(), APF_LABEL_DROP, max_jbs.data(), 2048), -1);
        EXPECT_EQ(apf_gen_add_ldm(err_gen.get(), APF_REG_R1, 16), -1);
        EXPECT_EQ(apf_gen_add_stm(err_gen.get(), APF_REG_R1, 16), -1);
        EXPECT_EQ(apf_gen_add_lddw(err_gen.get(), APF_REG_R0, 0), -1);
        EXPECT_EQ(apf_gen_add_lddw(err_gen.get(), APF_REG_R0, 20000), -1);
        EXPECT_EQ(apf_gen_add_stdw(err_gen.get(), APF_REG_R0, 0), -1);
        EXPECT_EQ(apf_gen_add_stdw(err_gen.get(), APF_REG_R0, 6), -1);
        EXPECT_EQ(apf_gen_add_cnt_and_pass(err_gen.get(), 0), -1);
        EXPECT_EQ(apf_gen_add_cnt_and_pass(err_gen.get(), 6), -1);
        EXPECT_EQ(apf_gen_add_cnt_and_drop(err_gen.get(), 0), -1);
        EXPECT_EQ(apf_gen_add_cnt_and_drop(err_gen.get(), 6), -1);
        EXPECT_EQ(apf_gen_add_div(err_gen.get(), APF_REG_R0, 0), -1);
        EXPECT_EQ(apf_gen_add_sh(err_gen.get(), APF_REG_R0, 32), -1);
        EXPECT_EQ(apf_gen_add_sh(err_gen.get(), APF_REG_R0, -32), -1);
        size_t err_len = 0;
        EXPECT_EQ(GenerateProgram(err_gen.get(), &err_len), nullptr);
    }
}

TEST(ApfGeneratorTest, testPacketTransmitAndRegisterInstructions) {
    // 1. Test APFv6.1 ALLOC_XMIT (R=1): allocate(266) -> 1 byte,
    //    allocate(267) -> rounds up to 274, allocate(300) -> 2 bytes (306),
    //    allocate_r0, and allocate_ext(512)
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_allocate(gen.get(), 266);
        apf_gen_add_allocate(gen.get(), 267);
        apf_gen_add_allocate(gen.get(), 300);
        apf_gen_add_allocate_r0(gen.get());
        apf_gen_add_allocate_ext(gen.get(), 512);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 18u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4054",
                      "7: allocate    (266)",
                      "8: allocate    (274)",
                      "10: allocate    (306)",
                      "12: allocate    r0",
                      "14: allocate    512",
                  }));
    }

    // 2. Test APFv6.1 transmit_without_csum() -> 1-byte ALLOC_XMIT (R=0, imm=0),
    //    transmit(14) -> 4-byte TRANSMIT_EXT_OPCODE (ip_ofs=14, csum_ofs=255),
    //    transmit_l4(14, 40, 26, 17, true) -> 2-byte ALLOC_XMIT (R=0),
    //    transmit_l4(14, 40, 26, 0, true) -> 2-byte ALLOC_XMIT with partial_csum=0x0,
    //    and transmit_l4(14, 40, 26, 0, false) -> extended TRANSMIT when is_udp mismatches
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_transmit_without_csum(gen.get());
        apf_gen_add_transmit(gen.get(), 14);
        apf_gen_add_transmit_l4(gen.get(), 14, 40, 26, 17, true);
        apf_gen_add_transmit_l4(gen.get(), 14, 40, 26, 0, true);
        apf_gen_add_transmit_l4(gen.get(), 14, 40, 26, 0, false);
        // Fallback to TRANSMIT_EXT_OPCODE when template does not match
        apf_gen_add_transmit_l4(gen.get(), 18, 44, 30, 0x1234, false);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 30u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4042",
                      "7: transmit",
                      "8: transmit    ip_ofs=14",
                      "12: transmitudp offload=ipv4/udp, partial_csum=0x11",
                      "14: transmitudp offload=ipv4/udp, partial_csum=0x0",
                      "16: transmit    ip_ofs=14, csum_ofs=40, csum_start=26, partial_csum=0x0000",
                      "23: transmit    ip_ofs=18, csum_ofs=44, csum_start=30, partial_csum=0x1234",
                  }));
    }

    // 2b. Test TCP checksum offload on APFv6.1 vs APFvNEXT:
    //     - APFv6.1 never emits ALLOC_XMIT types 1 or 5 (both fall back to extended TRANSMIT).
    //     - APFvNEXT (> APF_VERSION_61) emits ALLOC_XMIT types 1 and 5 for offsets 50 and 70.
    {
        // APFv6.1: TCP (csum_ofs 44/50 for IPv4, 64/70 for IPv6) falls back to extended TRANSMIT
        auto gen61 = AllocGen();
        ASSERT_NE(gen61, nullptr);
        apf_gen_add_transmit_l4(gen61.get(), 14, 50, 26, 0x11, false);
        apf_gen_add_transmit_l4(gen61.get(), 14, 44, 26, 0x11, false);
        // csum_ofs=64 with csum_start=22 matches type 7 (ether/ipv6/routeralert/icmp)
        apf_gen_add_transmit_l4(gen61.get(), 14, 64, 22, 0, false);
        size_t len61 = 0;
        auto buf61 = GenerateProgram(gen61.get(), &len61);
        ASSERT_NE(buf61, nullptr);
        EXPECT_EQ(DisassembleProgram(buf61.get(), len61),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4049",
                      "7: transmit    ip_ofs=14, csum_ofs=50, csum_start=26, partial_csum=0x0011",
                      "14: transmit    ip_ofs=14, csum_ofs=44, csum_start=26, partial_csum=0x0011",
                      "21: transmit    offload=ipv6/alert/icmp, partial_csum=0x0",
                  }));

        // APFvNEXT: TCP (csum_ofs 50/70) emits compact ALLOC_XMIT types 1 and 5
        auto gen_next = std::unique_ptr<apf_generator, void (*)(apf_generator*)>(
            apf_generator_alloc(APF_VERSION_61 + 1, 4096), apf_generator_free);
        ASSERT_NE(gen_next, nullptr);
        apf_gen_add_transmit_l4(gen_next.get(), 14, 50, 26, 0x11, false);
        apf_gen_add_transmit_l4(gen_next.get(), 14, 70, 22, 0x11, false);
        size_t len_next = 0;
        auto buf_next = GenerateProgram(gen_next.get(), &len_next);
        ASSERT_NE(buf_next, nullptr);
        EXPECT_EQ(DisassembleProgram(buf_next.get(), len_next),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4061",
                      "7: transmit    offload=ipv4/tcp, partial_csum=0x11",
                      "9: transmit    offload=ipv6/tcp, partial_csum=0x11",
                  }));
    }

    // 3. Test WRITE, EWRITE, PKTCOPY/DATACOPY, EPKTCOPY/EDATACOPY (including boundary lengths
    //    255, 256, and 511), and _R1 variants
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        const uint8_t init_data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        apf_gen_set_data(gen.get(), init_data, sizeof(init_data));
        apf_gen_add_write_u8(gen.get(), 0xAA);
        apf_gen_add_write_u16(gen.get(), 0xBBCC);
        apf_gen_add_write_u32(gen.get(), 0x11223344);
        apf_gen_add_pktcopy(gen.get(), 0, 14);
        apf_gen_add_pktcopy(gen.get(), 0, 255);
        apf_gen_add_pktcopy(gen.get(), 0, 256);
        apf_gen_add_pktcopy(gen.get(), 0, 511);
        apf_gen_add_pktcopy(gen.get(), 10, 300);
        apf_gen_add_datacopy(gen.get(), 3, 4);
        apf_gen_add_epktcopy(gen.get(), 255);
        apf_gen_add_epktcopy(gen.get(), 256);
        apf_gen_add_epktcopy(gen.get(), 300);
        apf_gen_add_epktcopy(gen.get(), 511);
        apf_gen_add_edatacopy(gen.get(), 16);
        apf_gen_add_edatacopy(gen.get(), 255);
        apf_gen_add_edatacopy(gen.get(), 256);
        apf_gen_add_edatacopy(gen.get(), 511);
        apf_gen_add_epktcopy_r1(gen.get());
        apf_gen_add_edatacopy_r1(gen.get());
        apf_gen_add_ewrite1(gen.get(), APF_REG_R0);
        apf_gen_add_ewrite2(gen.get(), APF_REG_R0);
        apf_gen_add_ewrite4(gen.get(), APF_REG_R1);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        4, deadbeef",
                      "7: debugbuf    size=3995",
                      "11: write       0xaa",
                      "13: write       0xbbcc",
                      "16: write       0x11223344",
                      "21: pktcopy     src=0, len=14",
                      "23: pktcopy     src=0, len=255",
                      "25: pktcopy     src=0, len=256",
                      "28: pktcopy     src=0, len=511",
                      "31: pktcopy     src=10, len=300",
                      "35: datacopy    src=3, (4)deadbeef",
                      "38: epktcopy    src=r0, len=255",
                      "41: epktcopy    src=r0, len=256",
                      "45: epktcopy    src=r0, len=300",
                      "49: epktcopy    src=r0, len=511",
                      "53: edatacopy   src=r0, len=16",
                      "56: edatacopy   src=r0, len=255",
                      "59: edatacopy   src=r0, len=256",
                      "63: edatacopy   src=r0, len=511",
                      "67: epktcopy    src=r0, len=r1",
                      "69: edatacopy   src=r0, len=r1",
                      "71: ewrite1     r0",
                      "73: ewrite2     r0",
                      "75: ewrite4     r1",
                  }));

        auto err_gen = AllocGen();
        ASSERT_NE(err_gen, nullptr);
        EXPECT_EQ(apf_gen_add_allocate(err_gen.get(), 0), -1);
        EXPECT_EQ(apf_gen_add_allocate_ext(err_gen.get(), 0), -1);
        EXPECT_EQ(apf_gen_add_transmit(err_gen.get(), 255), -1);
        EXPECT_EQ(apf_gen_add_transmit_l4(err_gen.get(), 255, 40, 26, 0, true), -1);
        EXPECT_EQ(apf_gen_add_transmit_l4(err_gen.get(), 14, 255, 26, 0, true), -1);
        EXPECT_EQ(apf_gen_add_pktcopy(err_gen.get(), 0, 0), -1);
        EXPECT_EQ(apf_gen_add_pktcopy(err_gen.get(), 0, 512), -1);
        EXPECT_EQ(apf_gen_add_pktcopy(err_gen.get(), 0x80000000u, 14), -1);
        EXPECT_EQ(apf_gen_add_datacopy(err_gen.get(), 0, 0), -1);
        EXPECT_EQ(apf_gen_add_datacopy(err_gen.get(), 2, 1), -1);
        EXPECT_EQ(apf_gen_add_datacopy(err_gen.get(), 3, 1), -1);
        EXPECT_EQ(apf_gen_add_epktcopy(err_gen.get(), 0), -1);
        EXPECT_EQ(apf_gen_add_edatacopy(err_gen.get(), 512), -1);
        size_t err_len = 0;
        EXPECT_EQ(GenerateProgram(err_gen.get(), &err_len), nullptr);
    }
}

TEST(ApfGeneratorTest, testJbsPtrMatchAndDataDeduplication) {
    const uint8_t target_mac[6] = {0x50, 0x6F, 0x9A, 0x01, 0x02, 0x03};

    auto gen = AllocGen();
    ASSERT_NE(gen, nullptr);
    apf_label lbl_drop = apf_gen_alloc_label(gen.get());
    ASSERT_EQ(lbl_drop.id, -2);
    // Match target_mac at destination MAC (offset 0) AND source MAC (offset 6).
    // Both calls reference the same 6-byte MAC; find_or_append_data_bytes
    // deduplicates it to 1 copy in JMPDATA.
    apf_gen_add_jbseq_at_offset(gen.get(), 0, lbl_drop, target_mac, sizeof(target_mac));
    apf_gen_add_jbsne_at_offset(gen.get(), 6, lbl_drop, target_mac, sizeof(target_mac));
    apf_gen_add_pass(gen.get());
    apf_gen_define_label(gen.get(), lbl_drop);
    apf_gen_add_drop(gen.get());

    size_t len = 0;
    auto buf = GenerateProgram(gen.get(), &len);
    ASSERT_NE(buf, nullptr);
    ASSERT_EQ(len, 25u);
    EXPECT_EQ(DisassembleProgram(buf.get(), len),
              (std::vector<std::string>{
                  "0: data        6, 506f9a010203",
                  "9: debugbuf    size=4047",
                  "13: jbsptreq    pktofs=0, (6), 24, @0[506f9a010203]",
                  "18: jbsptrne    pktofs=6, (6), 24, @0[506f9a010203]",
                  "23: pass",
                  "24: drop",
              }));

    // When JMPDATA already exceeds 510 bytes, JBSPTRMATCH gracefully falls back
    // to LI + JBSMATCH without latching APF_GEN_ERR_DATA_OVERFLOW.
    auto fallback_gen = AllocGen();
    ASSERT_NE(fallback_gen, nullptr);
    const std::vector<uint8_t> init_pool(512, 0xAA);
    ASSERT_EQ(apf_gen_set_data(fallback_gen.get(), init_pool.data(), init_pool.size()), 0);
    EXPECT_EQ(apf_gen_add_jbseq_at_offset(fallback_gen.get(), 0, APF_LABEL_DROP, target_mac,
                                          sizeof(target_mac)),
              0);
    EXPECT_EQ(apf_gen_get_error(fallback_gen.get(), nullptr), APF_GEN_OK);
    EXPECT_EQ(apf_gen_get_insn_count(fallback_gen.get()), 2u);
    size_t fb_len = 0;
    auto fb_buf = GenerateProgram(fallback_gen.get(), &fb_len);
    ASSERT_NE(fb_buf, nullptr);

    // Fallback to LI + JBSMATCH when pkt_offset > 255 (256), len > 16 (17), or cnt > 16 (17)
    {
        auto fb_bounds_gen = AllocGen();
        ASSERT_NE(fb_bounds_gen, nullptr);
        const std::vector<uint8_t> pat17(17, 0x11);
        uint8_t cnt17_bytes[17];
        for (uint8_t i = 0; i < 17; i++) cnt17_bytes[i] = i;
        EXPECT_EQ(apf_gen_add_jbseq_at_offset(fb_bounds_gen.get(), 256, APF_LABEL_DROP, target_mac,
                                              sizeof(target_mac)),
                  0);
        EXPECT_EQ(apf_gen_add_jbsne_at_offset(fb_bounds_gen.get(), 0, APF_LABEL_DROP, pat17.data(),
                                              17),
                  0);
        EXPECT_EQ(apf_gen_add_jbseq_at_offset_multi(fb_bounds_gen.get(), 10, APF_LABEL_PASS,
                                                    cnt17_bytes, 17, 1),
                  0);
        size_t b_len = 0;
        auto b_buf = GenerateProgram(fb_bounds_gen.get(), &b_len);
        ASSERT_NE(b_buf, nullptr);
        EXPECT_EQ(
            DisassembleProgram(b_buf.get(), b_len),
            (std::vector<std::string>{
                "0: data        0,",
                "3: debugbuf    size=4008",
                "7: li          r0, 256",
                "10: jbseq       r0, (6), DROP, 506f9a010203",
                "19: li          r0, 0",
                "20: jbsne       r0, (17), DROP, 1111111111111111111111111111111111",
                "40: li          r0, 10",
                "42: jbseq       r0, (1), PASS, "
                "{ 00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f, 10 }[17]",
            }));
    }

    // Odd-length JMPDATA pads 1 zero byte so JBSPTRMATCH pattern lands at even offset (@6)
    {
        auto odd_gen = AllocGen();
        ASSERT_NE(odd_gen, nullptr);
        const uint8_t odd5[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
        ASSERT_EQ(apf_gen_set_data(odd_gen.get(), odd5, sizeof(odd5)), 0);
        ASSERT_EQ(apf_gen_add_jbseq_at_offset(odd_gen.get(), 0, APF_LABEL_DROP, target_mac,
                                              sizeof(target_mac)),
                  0);
        size_t odd_len = 0;
        auto odd_buf = GenerateProgram(odd_gen.get(), &odd_len);
        ASSERT_NE(odd_buf, nullptr);
        EXPECT_EQ(DisassembleProgram(odd_buf.get(), odd_len),
                  (std::vector<std::string>{
                      "0: data        12, 010203040500506f9a010203",
                      "15: debugbuf    size=4048",
                      "19: jbsptreq    pktofs=0, (6), DROP, @6[506f9a010203]",
                  }));
    }

    // Pattern placed at exact max even offset 510 still uses JBSPTRMATCH (@510)
    {
        auto gen510 = AllocGen();
        ASSERT_NE(gen510, nullptr);
        const std::vector<uint8_t> pool510(510, 0xAA);
        ASSERT_EQ(apf_gen_set_data(gen510.get(), pool510.data(), pool510.size()), 0);
        ASSERT_EQ(apf_gen_add_jbseq_at_offset(gen510.get(), 0, APF_LABEL_DROP, target_mac,
                                              sizeof(target_mac)),
                  0);
        size_t len510 = 0;
        auto buf510 = GenerateProgram(gen510.get(), &len510);
        ASSERT_NE(buf510, nullptr);
        std::vector<std::string> disas510 = DisassembleProgram(buf510.get(), len510);
        ASSERT_EQ(disas510.size(), 3u);
        EXPECT_EQ(disas510[2], "523: jbsptreq    pktofs=0, (6), DROP, @510[506f9a010203]");
    }

    // Multi-pattern call where 1st pattern fits at 508 but 2nd lands at 512 falls back
    // entirely to LI + JBSMATCH and restores JMPDATA length to 508
    {
        auto gen508 = AllocGen();
        ASSERT_NE(gen508, nullptr);
        const std::vector<uint8_t> pool508(508, 0xAA);
        ASSERT_EQ(apf_gen_set_data(gen508.get(), pool508.data(), pool508.size()), 0);
        const uint8_t two_pats[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
        ASSERT_EQ(apf_gen_add_jbsne_at_offset_multi(gen508.get(), 0, APF_LABEL_DROP, two_pats, 2,
                                                    4),
                  0);
        size_t len508 = 0;
        auto buf508 = GenerateProgram(gen508.get(), &len508);
        ASSERT_NE(buf508, nullptr);
        std::vector<std::string> disas508 = DisassembleProgram(buf508.get(), len508);
        ASSERT_EQ(disas508.size(), 4u);
        EXPECT_EQ(disas508[0], "0: data        508, " + std::string(508 * 2, 'a'));
        EXPECT_EQ(disas508[2], "515: li          r0, 0");
        EXPECT_EQ(disas508[3], "516: jbsne       r0, (4), DROP, { 11223344, 55667788 }[2]");
    }

    // Invalid cnt/len or duplicate patterns fail upfront without emitting a dangling LI R0
    auto err_gen = AllocGen();
    ASSERT_NE(err_gen, nullptr);
    const std::vector<uint8_t> oversize_pattern(2048, 0x11);
    EXPECT_EQ(apf_gen_add_jbsne_at_offset(err_gen.get(), 300, APF_LABEL_DROP,
                                          oversize_pattern.data(), 2048),
              -1);
    EXPECT_EQ(apf_gen_get_insn_count(err_gen.get()), 0u);
    const uint8_t dup_macs[12] = {
        0x50, 0x6F, 0x9A, 0x01, 0x02, 0x03,
        0x50, 0x6F, 0x9A, 0x01, 0x02, 0x03,
    };
    EXPECT_EQ(apf_gen_add_jbsne_at_offset_multi(err_gen.get(), 0, APF_LABEL_DROP, dup_macs, 2, 6),
              -1);
    EXPECT_EQ(apf_gen_add_jbsne_at_offset(err_gen.get(), 0x80000000u, APF_LABEL_DROP, target_mac,
                                          sizeof(target_mac)),
              -1);
    EXPECT_EQ(apf_gen_get_insn_count(err_gen.get()), 0u);
}

TEST(ApfGeneratorTest, testApfV6AndV61ExtendedInstructions) {
    auto gen = AllocGen();
    ASSERT_NE(gen, nullptr);

    // 1. JNSET / JNSET_R1 and multi-match JBSMATCH
    const uint8_t multi_seqs[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    apf_gen_add_jnset(gen.get(), 0x04, APF_LABEL_DROP);
    apf_gen_add_jnset_r1(gen.get(), APF_LABEL_PASS);
    apf_gen_add_jbsne_multi(gen.get(), APF_LABEL_DROP, multi_seqs, 2, 4);
    apf_gen_add_jbseq_multi(gen.get(), APF_LABEL_PASS, multi_seqs, 2, 4);

    // 2. JONEOF / JNONEOF (cnt=3, 2-byte elements: 0x0800, 0x0806, 0x86DD)
    const uint32_t ethertypes[3] = {0x0800, 0x0806, 0x86DD};
    apf_gen_add_joneof(gen.get(), APF_REG_R0, APF_LABEL_DROP, ethertypes, 3);
    apf_gen_add_jnoneof(gen.get(), APF_REG_R1, APF_LABEL_PASS, ethertypes, 3);

    // 3. JDNSQMATCH, JDNSAMATCH, JDNSQMATCH1, JDNSQMATCH2 (ne/eq & normal/safe)
    const uint8_t dns_qname[] = {
        0x02, 'a', 'a', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00, 0x00,
    };
    apf_gen_add_jdnsqne(gen.get(), APF_LABEL_DROP, 12, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsqeq(gen.get(), APF_LABEL_PASS, 12, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsqnesafe(gen.get(), APF_LABEL_DROP, 12, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsqeqsafe(gen.get(), APF_LABEL_PASS, 12, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsane(gen.get(), APF_LABEL_DROP, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsaeq(gen.get(), APF_LABEL_PASS, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsanesafe(gen.get(), APF_LABEL_DROP, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsaeqsafe(gen.get(), APF_LABEL_PASS, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsqne1(gen.get(), APF_LABEL_DROP, 0x00FF, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsqeq1(gen.get(), APF_LABEL_PASS, 0x00FF, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsqnesafe1(gen.get(), APF_LABEL_DROP, 0x00FF, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsqeqsafe1(gen.get(), APF_LABEL_PASS, 0x00FF, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsqne2(gen.get(), APF_LABEL_DROP, 1, 28, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsqeq2(gen.get(), APF_LABEL_PASS, 1, 28, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsqnesafe2(gen.get(), APF_LABEL_DROP, 1, 28, dns_qname, sizeof(dns_qname));
    apf_gen_add_jdnsqeqsafe2(gen.get(), APF_LABEL_PASS, 1, 28, dns_qname, sizeof(dns_qname));

    // 4. Counter PASS/DROP
    apf_gen_add_cnt_and_pass(gen.get(), 7);
    apf_gen_add_cnt_and_drop(gen.get(), 300);

    size_t len = 0;
    auto buf = GenerateProgram(gen.get(), &len);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
    EXPECT_EQ(DisassembleProgram(buf.get(), len),
              (std::vector<std::string>{
                  "0: data        0,",
                  "3: debugbuf    size=2584",
                  "7: jnset       r0, 0x4, DROP",
                  "12: jnset       r0, r1, PASS",
                  "15: jbsne       r0, (4), DROP, { 11223344, 55667788 }[2]",
                  "28: jbseq       r0, (4), PASS, { 11223344, 55667788 }[2]",
                  "41: joneof      r0, DROP, { 2048, 2054, 34525 }",
                  "53: jnoneof     r1, PASS, { 2048, 2054, 34525 }",
                  "63: jdnsqne     r0, DROP, PTR, (2)AA(5)LOCAL(0)(0)",
                  "78: jdnsqeq     r0, PASS, PTR, (2)AA(5)LOCAL(0)(0)",
                  "93: jdnsqnesafe r0, DROP, PTR, (2)AA(5)LOCAL(0)(0)",
                  "108: jdnsqeqsafe r0, PASS, PTR, (2)AA(5)LOCAL(0)(0)",
                  "123: jdnsane     r0, DROP, (2)AA(5)LOCAL(0)(0)",
                  "137: jdnsaeq     r0, PASS, (2)AA(5)LOCAL(0)(0)",
                  "151: jdnsanesafe r0, DROP, (2)AA(5)LOCAL(0)(0)",
                  "165: jdnsaeqsafe r0, PASS, (2)AA(5)LOCAL(0)(0)",
                  "179: jdnsqne1    r0, DROP, 255, (2)AA(5)LOCAL(0)(0)",
                  "195: jdnsqeq1    r0, PASS, 255, (2)AA(5)LOCAL(0)(0)",
                  "211: jdnsqnesafe1r0, DROP, 255, (2)AA(5)LOCAL(0)(0)",
                  "227: jdnsqeqsafe1r0, PASS, 255, (2)AA(5)LOCAL(0)(0)",
                  "243: jdnsqne2    r0, DROP, A, AAAA, (2)AA(5)LOCAL(0)(0)",
                  "259: jdnsqeq2    r0, PASS, A, AAAA, (2)AA(5)LOCAL(0)(0)",
                  "275: jdnsqnesafe2r0, DROP, A, AAAA, (2)AA(5)LOCAL(0)(0)",
                  "291: jdnsqeqsafe2r0, PASS, A, AAAA, (2)AA(5)LOCAL(0)(0)",
                  "307: pass        counter=7",
                  "309: drop        counter=300",
              }));

    // Calling builders with invalid arguments after generate() preserves ALREADY_GENERATED
    EXPECT_EQ(apf_gen_add_joneof(gen.get(), APF_REG_R0, APF_LABEL_DROP, ethertypes, 1), -1);
    EXPECT_EQ(apf_gen_get_error(gen.get(), nullptr), APF_GEN_ERR_ALREADY_GENERATED);

    // 5. Boundary coverage for JONEOF (1-, 3-, 4-byte elements; cnt=2 and cnt=33),
    //    JBSMATCH multi (cnt=32), and DNS name lists with 0xFF wildcard and multiple names
    {
        auto b_gen = AllocGen();
        ASSERT_NE(b_gen, nullptr);
        const uint32_t u8_set[2] = {6, 17};
        const uint32_t u24_set[2] = {1, 0x010203};
        const uint32_t u32_set[2] = {1, 0x01020304};
        uint32_t max_set[33];
        for (uint8_t i = 0; i < 33; i++) max_set[i] = i;
        uint8_t seq32[32];
        for (uint8_t i = 0; i < 32; i++) seq32[i] = i;
        const uint8_t wildcard_multi_qnames[] = {
            0xFF, 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
            0x01, 'b',  0x05, 'l', 'o', 'c', 'a', 'l', 0x00, 0x00,
        };
        EXPECT_EQ(apf_gen_add_joneof(b_gen.get(), APF_REG_R0, APF_LABEL_DROP, u8_set, 2), 0);
        EXPECT_EQ(apf_gen_add_joneof(b_gen.get(), APF_REG_R0, APF_LABEL_DROP, u24_set, 2), 0);
        EXPECT_EQ(apf_gen_add_jnoneof(b_gen.get(), APF_REG_R1, APF_LABEL_PASS, u32_set, 2), 0);
        EXPECT_EQ(apf_gen_add_joneof(b_gen.get(), APF_REG_R0, APF_LABEL_DROP, max_set, 33), 0);
        EXPECT_EQ(apf_gen_add_jbsne_multi(b_gen.get(), APF_LABEL_DROP, seq32, 32, 1), 0);
        EXPECT_EQ(apf_gen_add_jbseq_multi(b_gen.get(), APF_LABEL_PASS, seq32, 32, 1), 0);
        EXPECT_EQ(apf_gen_add_jdnsqne(b_gen.get(), APF_LABEL_DROP, 12, wildcard_multi_qnames,
                                      sizeof(wildcard_multi_qnames)),
                  0);
        size_t b_len = 0;
        auto b_buf = GenerateProgram(b_gen.get(), &b_len);
        ASSERT_NE(b_buf, nullptr);
        EXPECT_EQ(
            DisassembleProgram(b_buf.get(), b_len),
            (std::vector<std::string>{
                "0: data        0,",
                "3: debugbuf    size=3904",
                "7: joneof      r0, DROP, { 6, 17 }",
                "13: joneof      r0, DROP, { 1, 66051 }",
                "23: jnoneof     r1, PASS, { 1, 16909060 }",
                "35: joneof      r0, DROP, { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, "
                "15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 }",
                "72: jbsne       r0, (1), DROP, { 00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, "
                "0c, 0d, 0e, 0f, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1a, 1b, 1c, 1d, 1e, 1f "
                "}[32]",
                "109: jbseq       r0, (1), PASS, { 00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, "
                "0b, 0c, 0d, 0e, 0f, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1a, 1b, 1c, 1d, 1e, "
                "1f }[32]",
                "146: jdnsqne     r0, DROP, PTR, (*)(5)LOCAL(0)(1)B(5)LOCAL(0)(0)",
            }));
    }

    auto err_gen = AllocGen();
    ASSERT_NE(err_gen, nullptr);
    EXPECT_EQ(apf_gen_add_jset(err_gen.get(), 0, APF_LABEL_DROP), -1);
    EXPECT_EQ(apf_gen_add_jnset(err_gen.get(), 0, APF_LABEL_DROP), -1);
    EXPECT_EQ(apf_gen_add_jdnsqne2(err_gen.get(), APF_LABEL_DROP, 1, 1, dns_qname,
                                   sizeof(dns_qname)),
              -1);
    EXPECT_EQ(apf_gen_add_joneof(err_gen.get(), APF_REG_R0, APF_LABEL_DROP, ethertypes, 1), -1);
    EXPECT_EQ(apf_gen_add_jnoneof(err_gen.get(), APF_REG_R0, APF_LABEL_DROP, ethertypes, 34), -1);
    uint8_t seq33[33] = {};
    EXPECT_EQ(apf_gen_add_jbsne_multi(err_gen.get(), APF_LABEL_DROP, seq33, 33, 1), -1);
    EXPECT_EQ(apf_gen_add_jbseq_multi(err_gen.get(), APF_LABEL_PASS, seq33, 33, 1), -1);
    // Duplicate elements in JONEOF must be rejected (interpreter uses XOR toggle)
    const uint32_t dup_values[2] = {0x0800, 0x0800};
    EXPECT_EQ(apf_gen_add_joneof(err_gen.get(), APF_REG_R0, APF_LABEL_DROP, dup_values, 2), -1);
    // Duplicate patterns in multi-sequence JBSMATCH must be rejected
    const uint8_t dup_seqs[8] = {0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44};
    EXPECT_EQ(apf_gen_add_jbsne_multi(err_gen.get(), APF_LABEL_DROP, dup_seqs, 2, 4), -1);
    // Malformed DNS name encodings must be rejected
    const uint8_t bad_qname_short[] = {0x02, 'a', 'a', 0x00};
    const uint8_t bad_qname_early_double_nul[] = {
        0x01, 'a', 0x00, 0x00, 0x01, 'b', 0x00, 0x00,
    };
    const uint8_t bad_qname_truncated_label[] = {0x05, 'a', 'b', 0x00, 0x00};
    const uint8_t bad_qname_nul_in_label[] = {0x02, 'a', 0x00, 0x00, 0x00};
    const uint8_t bad_qname_trailing_wildcard[] = {0x01, 'a', 0x00, 0xFF, 0x00};
    EXPECT_EQ(apf_gen_add_jdnsqne(err_gen.get(), APF_LABEL_DROP, 12, bad_qname_short,
                                  sizeof(bad_qname_short)),
              -1);
    EXPECT_EQ(apf_gen_add_jdnsqne(err_gen.get(), APF_LABEL_DROP, 12, bad_qname_early_double_nul,
                                  sizeof(bad_qname_early_double_nul)),
              -1);
    EXPECT_EQ(apf_gen_add_jdnsqne(err_gen.get(), APF_LABEL_DROP, 12, bad_qname_truncated_label,
                                  sizeof(bad_qname_truncated_label)),
              -1);
    EXPECT_EQ(apf_gen_add_jdnsqne(err_gen.get(), APF_LABEL_DROP, 12, bad_qname_nul_in_label,
                                  sizeof(bad_qname_nul_in_label)),
              -1);
    EXPECT_EQ(apf_gen_add_jdnsqne(err_gen.get(), APF_LABEL_DROP, 12, bad_qname_trailing_wildcard,
                                  sizeof(bad_qname_trailing_wildcard)),
              -1);
    EXPECT_EQ(apf_gen_add_cnt_and_pass(err_gen.get(), 0), -1);
    EXPECT_EQ(apf_gen_add_cnt_and_drop(err_gen.get(), 0), -1);
    size_t err_len = 0;
    EXPECT_EQ(GenerateProgram(err_gen.get(), &err_len), nullptr);
}

TEST(ApfGeneratorTest, testDataCopyAndDeduplication) {
    // 1. Pre-populating initial JMPDATA at the start of the program works, and
    //    calling apf_gen_set_data a second time or after another instruction fails
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        const uint8_t hdr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        EXPECT_EQ(apf_gen_set_data(gen.get(), hdr, sizeof(hdr)), 0);
        EXPECT_EQ(apf_gen_set_data(gen.get(), hdr, sizeof(hdr)), -1);

        auto gen2 = AllocGen();
        ASSERT_NE(gen2, nullptr);
        apf_gen_add_pass(gen2.get());
        EXPECT_EQ(apf_gen_set_data(gen2.get(), hdr, sizeof(hdr)), -1);
    }

    // 2. Deduplicate overlapping/repeated slices (including against apf_gen_set_data bytes)
    //    and emit DATACOPY with 3 + rel_ofs and boundary lengths (255, 256, 511)
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        const uint8_t hdr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        ASSERT_EQ(apf_gen_set_data(gen.get(), hdr, sizeof(hdr)), 0);
        // Full slice matches pre-populated set_data bytes at JMPDATA offset 0 -> program offset 3
        apf_gen_add_data_copy(gen.get(), hdr, sizeof(hdr));
        // Sub-slice {0xBB, 0xCC, 0xDD} matches at unaligned JMPDATA offset 1 -> program offset 4
        EXPECT_EQ(apf_gen_find_or_append_data(gen.get(), hdr + 1, 3), 4);
        apf_gen_add_data_copy(gen.get(), hdr + 1, 3);

        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 19u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        6, aabbccddeeff",
                      "9: debugbuf    size=4053",
                      "13: datacopy    src=3, (6)aabbccddeeff",
                      "16: datacopy    src=4, (3)bbccdd",
                  }));

        auto dcopy_gen = AllocGen();
        ASSERT_NE(dcopy_gen, nullptr);
        const std::vector<uint8_t> pool511(511, 0x11);
        ASSERT_EQ(apf_gen_set_data(dcopy_gen.get(), pool511.data(), pool511.size()), 0);
        EXPECT_EQ(apf_gen_add_datacopy(dcopy_gen.get(), 3, 255), 0);
        EXPECT_EQ(apf_gen_add_datacopy(dcopy_gen.get(), 3, 256), 0);
        EXPECT_EQ(apf_gen_add_datacopy(dcopy_gen.get(), 3, 511), 0);
        size_t dc_len = 0;
        auto dc_buf = GenerateProgram(dcopy_gen.get(), &dc_len);
        ASSERT_NE(dc_buf, nullptr);
        std::vector<std::string> dc_disas = DisassembleProgram(dc_buf.get(), dc_len);
        ASSERT_EQ(dc_disas.size(), 5u);
        EXPECT_EQ(dc_disas[2], "518: datacopy    src=3, (255)" + std::string(255 * 2, '1'));
        EXPECT_EQ(dc_disas[3], "521: datacopy    src=3, (256)" + std::string(256 * 2, '1'));
        EXPECT_EQ(dc_disas[4], "525: datacopy    src=3, (511)" + std::string(511 * 2, '1'));
    }

    // 3. Multi-chunk splitting boundary: 511 bytes (1 instruction) vs 512 bytes (511 + 1),
    //    and 600 bytes (511 + 89)
    {
        auto gen511 = AllocGen();
        ASSERT_NE(gen511, nullptr);
        const std::vector<uint8_t> p511(511, 0x42);
        EXPECT_EQ(apf_gen_add_data_copy(gen511.get(), p511.data(), p511.size()), 0);
        EXPECT_EQ(apf_gen_get_insn_count(gen511.get()), 1u);

        auto gen512 = AllocGen();
        ASSERT_NE(gen512, nullptr);
        std::vector<uint8_t> p512(512, 0x44);
        p512[511] = 0x99;
        EXPECT_EQ(apf_gen_add_data_copy(gen512.get(), p512.data(), p512.size()), 0);
        EXPECT_EQ(apf_gen_get_insn_count(gen512.get()), 2u);
        size_t len512 = 0;
        auto buf512 = GenerateProgram(gen512.get(), &len512);
        ASSERT_NE(buf512, nullptr);
        std::vector<std::string> disas512 = DisassembleProgram(buf512.get(), len512);
        ASSERT_EQ(disas512.size(), 4u);
        EXPECT_EQ(disas512[2], "519: datacopy    src=3, (511)" + std::string(511 * 2, '4'));
        EXPECT_EQ(disas512[3], "523: datacopy    src=514, (1)99");

        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        uint8_t large_payload[600];
        for (size_t i = 0; i < sizeof(large_payload); i++) {
            large_payload[i] = (i < 511) ? static_cast<uint8_t>(i & 0x7f) : 0xAA;
        }
        apf_gen_add_data_copy(gen.get(), large_payload, sizeof(large_payload));
        EXPECT_EQ(apf_gen_get_insn_count(gen.get()), 2u);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 615u);
        std::vector<std::string> disas = DisassembleProgram(buf.get(), len);
        ASSERT_EQ(disas.size(), 4u);
        EXPECT_EQ(disas[1], "603: debugbuf    size=3457");
        EXPECT_EQ(disas[3], "611: datacopy    src=514, (89)" + std::string(89 * 2, 'a'));
    }

    // 4. Multi-chunk rollback on JMPDATA overflow preserves insn count and err_insn_index,
    //    and calling apf_gen_set_data() after a failed 70000-byte data_copy does not leak memory
    {
        auto gen = AllocGen(APF_VERSION_61, 131072);
        ASSERT_NE(gen, nullptr);
        const std::vector<uint8_t> init_pool(65000, 0x11);
        ASSERT_EQ(apf_gen_set_data(gen.get(), init_pool.data(), init_pool.size()), 0);
        ASSERT_EQ(apf_gen_add_pass(gen.get()), 0);
        // Chunk 1 (511 bytes of 0x22) fits in 65511 <= 65535, but chunk 2 (89 bytes of 0x33)
        // overflows 65535; both JMPDATA and the emitted chunk-1 instruction must roll back.
        std::vector<uint8_t> overflow_payload(600, 0x22);
        for (size_t i = 511; i < overflow_payload.size(); i++) {
            overflow_payload[i] = 0x33;
        }
        EXPECT_EQ(apf_gen_add_data_copy(gen.get(), overflow_payload.data(),
                                        overflow_payload.size()),
                  -1);
        EXPECT_EQ(apf_gen_get_insn_count(gen.get()), 1u);
        size_t err_idx = 99;
        EXPECT_EQ(apf_gen_get_error(gen.get(), &err_idx), APF_GEN_ERR_DATA_OVERFLOW);
        EXPECT_EQ(err_idx, 1u);

        auto leak_gen = AllocGen(APF_VERSION_61, 131072);
        ASSERT_NE(leak_gen, nullptr);
        std::vector<uint8_t> huge_payload(70000);
        for (size_t i = 0; i < huge_payload.size(); i++) {
            huge_payload[i] = static_cast<uint8_t>((i / 511) + 1);
        }
        EXPECT_EQ(apf_gen_add_data_copy(leak_gen.get(), huge_payload.data(), huge_payload.size()),
                  -1);
        EXPECT_EQ(apf_gen_get_error(leak_gen.get(), nullptr), APF_GEN_ERR_DATA_OVERFLOW);
        const uint8_t small_data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        EXPECT_EQ(apf_gen_set_data(leak_gen.get(), small_data, sizeof(small_data)), 0);
    }
}

TEST(ApfGeneratorTest, testBranchLabelsAndTerminalTargets) {
    // 1. User-defined allocated labels + iterative branch shrinking
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_label lbl_ipv4 = apf_gen_alloc_label(gen.get());
        apf_label lbl_drop = apf_gen_alloc_label(gen.get());
        ASSERT_EQ(lbl_ipv4.id, -2);
        ASSERT_EQ(lbl_drop.id, -3);

        apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
        apf_gen_add_jeq(gen.get(), 0x0800, lbl_ipv4);
        apf_gen_add_cnt_and_drop(gen.get(), 7);
        apf_gen_define_label(gen.get(), lbl_ipv4);
        apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
        apf_gen_add_jne(gen.get(), 17, lbl_drop);
        apf_gen_add_pass(gen.get());
        apf_gen_define_label(gen.get(), lbl_drop);
        apf_gen_add_drop(gen.get());

        EXPECT_EQ(apf_gen_get_insn_count(gen.get()), 7u);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 23u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4045",
                      "7: ldh         r0, [12]",
                      "9: jeq         r0, 0x800, 16",
                      "14: drop        counter=7",
                      "16: ldb         r0, [23]",
                      "18: jne         r0, 0x11, 22",
                      "21: pass",
                      "22: drop",
                  }));
    }

    // 2. Terminal verdict targets: APF_LABEL_PASS, APF_LABEL_DROP,
    //    apf_gen_cnt_pass_label, apf_gen_cnt_drop_label
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_ldb(gen.get(), APF_REG_R0, 1);
        apf_gen_add_jeq(gen.get(), 1, APF_LABEL_PASS);
        apf_gen_add_jeq(gen.get(), 2, APF_LABEL_DROP);
        apf_gen_add_jeq(gen.get(), 3, apf_gen_cnt_pass_label(7));
        apf_gen_add_jeq(gen.get(), 4, apf_gen_cnt_drop_label(8));
        apf_gen_add_pass(gen.get());

        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 22u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4042",
                      "7: ldb         r0, [1]",
                      "9: jeq         r0, 0x1, PASS",
                      "12: jeq         r0, 0x2, DROP",
                      "15: jeq         r0, 0x3, cnt_and_pass[cnt=7]",
                      "18: jeq         r0, 0x4, cnt_and_drop[cnt=8]",
                      "21: pass",
                  }));
    }

    // 3. Error cases: duplicate labels, undefined labels, and invalid counter labels
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        EXPECT_EQ(apf_gen_cnt_pass_label(0).id, APF_LABEL_INVALID.id);
        EXPECT_EQ(apf_gen_cnt_pass_label(6).id, APF_LABEL_INVALID.id);
        EXPECT_EQ(apf_gen_cnt_drop_label(6).id, APF_LABEL_INVALID.id);
        EXPECT_EQ(apf_gen_cnt_drop_label(20000).id, APF_LABEL_INVALID.id);
        EXPECT_EQ(apf_gen_add_jeq(gen.get(), 1, apf_gen_cnt_pass_label(6)), -1);
        EXPECT_EQ(apf_gen_add_jeq(gen.get(), 1, apf_gen_cnt_drop_label(20000)), -1);
        // Terminal labels cannot be defined as intra-program branch anchors
        EXPECT_EQ(apf_gen_define_label(gen.get(), APF_LABEL_PASS), -1);
        apf_label lbl1 = apf_gen_alloc_label(gen.get());
        apf_label lbl_undef = apf_gen_alloc_label(gen.get());
        EXPECT_EQ(apf_gen_define_label(gen.get(), lbl1), 0);
        // Duplicate label definition must fail
        EXPECT_EQ(apf_gen_define_label(gen.get(), lbl1), -1);
        // Referencing an undefined allocated label causes apf_gen_generate() to fail
        auto undef_gen = AllocGen();
        ASSERT_NE(undef_gen, nullptr);
        apf_label unanchored = apf_gen_alloc_label(undef_gen.get());
        EXPECT_NE(unanchored.id, lbl_undef.id);
        apf_gen_add_jmp(undef_gen.get(), unanchored);
        size_t len = 0;
        EXPECT_EQ(GenerateProgram(undef_gen.get(), &len), nullptr);
        size_t err_idx = 99;
        EXPECT_EQ(apf_gen_get_error(undef_gen.get(), &err_idx), APF_GEN_ERR_UNDEFINED_LABEL);
        EXPECT_EQ(err_idx, 0u);
    }
}

/*
 * The following four full-program tests are APFv6.1 re-encodings of the
 * real-world APFv4 filter programs from ApfTest.java:
 *   - testFullApfV4ProgramGenerationIPV6
 *   - testFullApfV4ProgramGenerationIPV4
 *   - testFullApfV4ProgramGenerationNatTKeepAliveV4
 *   - testInfiniteLifetimeFullApfV4ProgramGeneration
 * Because libapfgenerator targets APFv6.1+, each program begins with the
 * auto-emitted 7-byte prologue ("0: data 0," + "3: debugbuf size=...") and
 * shifts user counter indices to start at APF_COUNTER_MIN_USER (7).
 */
TEST(ApfGeneratorTest, testFullApfV4ProgramGenerationIPV6) {
    auto gen = AllocGen();
    ASSERT_NE(gen, nullptr);
    const apf_label lbl_102 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_116 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_159 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_207 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_231 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_249 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_283 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_496 = apf_gen_alloc_label(gen.get());
    apf_gen_add_lddw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_add(gen.get(), APF_REG_R0, 1);
    apf_gen_add_stdw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jlt(gen.get(), 0x600, apf_gen_cnt_drop_label(33));
    apf_gen_add_jeq(gen.get(), 0x88a2, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88a4, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88b8, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88cd, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88e1, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88e3, apf_gen_cnt_drop_label(34));
    apf_gen_add_jne(gen.get(), 0x806, lbl_116);
    apf_gen_add_li(gen.get(), APF_REG_R0, 14);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(15), "000108000604");
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x1, lbl_102);
    apf_gen_add_jne(gen.get(), 0x2, apf_gen_cnt_pass_label(16));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 28);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_drop_label(35));
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(17), "ffffffffffff");

    apf_gen_define_label(gen.get(), lbl_102);
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 38);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_drop_label(22));
    apf_gen_add_cnt_and_pass(gen.get(), 8);

    apf_gen_define_label(gen.get(), lbl_116);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jne(gen.get(), 0x800, lbl_207);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
    apf_gen_add_jne(gen.get(), 0x11, lbl_159);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jset(gen.get(), 0x1fff, lbl_159);
    apf_gen_add_ldm(gen.get(), APF_REG_R1, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_ldhx(gen.get(), APF_REG_R0, 16);
    apf_gen_add_jne(gen.get(), 0x44, lbl_159);
    apf_gen_add_li(gen.get(), APF_REG_R0, 50);
    apf_gen_add_add_reg(gen.get(), APF_REG_R0);
    AddJbsneHex(gen.get(), lbl_159, "e212507c6345");
    apf_gen_add_cnt_and_pass(gen.get(), 9);

    apf_gen_define_label(gen.get(), lbl_159);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 30);
    apf_gen_add_and(gen.get(), APF_REG_R0, 240);
    apf_gen_add_jeq(gen.get(), 0xe0, apf_gen_cnt_drop_label(27));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 30);
    apf_gen_add_jeq(gen.get(), 0xffffffffu, apf_gen_cnt_drop_label(25));
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(12), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 24);
    apf_gen_add_cnt_and_pass(gen.get(), 10);

    apf_gen_define_label(gen.get(), lbl_207);
    apf_gen_add_jeq(gen.get(), 0x86dd, lbl_231);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(18), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 20);

    apf_gen_define_label(gen.get(), lbl_231);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x3a, lbl_249);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 38);
    apf_gen_add_jeq(gen.get(), 0xff, apf_gen_cnt_drop_label(32));
    apf_gen_add_cnt_and_pass(gen.get(), 14);

    apf_gen_define_label(gen.get(), lbl_249);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 54);
    apf_gen_add_jeq(gen.get(), 0x85, apf_gen_cnt_drop_label(28));
    apf_gen_add_jne(gen.get(), 0x88, lbl_283);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), lbl_283, "ff0200000000000000000000000000");
    apf_gen_add_cnt_and_drop(gen.get(), 29);

    apf_gen_define_label(gen.get(), lbl_283);
    apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_PACKET_SIZE);
    apf_gen_add_jne(gen.get(), 0xa6, lbl_496);
    apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_FILTER_AGE);
    apf_gen_add_jgt(gen.get(), 0x254, lbl_496);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), lbl_496, "e212507c6345648788fd6df086dd68");
    apf_gen_add_li(gen.get(), APF_REG_R0, 18);
    AddJbsneHex(
        gen.get(), lbl_496,
        "00703afffe800000000000002a0079e10abc1539fe80000000000000e01250fffe7c63458600");
    apf_gen_add_li(gen.get(), APF_REG_R0, 58);
    AddJbsneHex(gen.get(), lbl_496, "4000");
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 60);
    apf_gen_add_jlt(gen.get(), 0x254, lbl_496);
    apf_gen_add_li(gen.get(), APF_REG_R0, 62);
    AddJbsneHex(gen.get(), lbl_496, "0000000000000000");
    apf_gen_add_li(gen.get(), APF_REG_R0, 78);
    AddJbsneHex(gen.get(), lbl_496, "19050000");
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 82);
    apf_gen_add_jlt(gen.get(), 0x254, lbl_496);
    apf_gen_add_li(gen.get(), APF_REG_R0, 86);
    AddJbsneHex(gen.get(), lbl_496,
                "2001486048600000000000000000646420014860486000000000000000000064");
    apf_gen_add_li(gen.get(), APF_REG_R0, 118);
    AddJbsneHex(gen.get(), lbl_496, "030440c0");
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 122);
    apf_gen_add_jlt(gen.get(), 0x254, lbl_496);
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 126);
    apf_gen_add_jlt(gen.get(), 0x254, lbl_496);
    apf_gen_add_li(gen.get(), APF_REG_R0, 130);
    AddJbsneHex(gen.get(), lbl_496, "00000000");
    apf_gen_add_li(gen.get(), APF_REG_R0, 134);
    AddJbsneHex(gen.get(), lbl_496, "2a0079e10abc15390000000000000000");
    apf_gen_add_cnt_and_drop(gen.get(), 21);

    apf_gen_define_label(gen.get(), lbl_496);
    apf_gen_add_cnt_and_pass(gen.get(), 13);

    size_t len = 0;
    auto buf = GenerateProgram(gen.get(), &len);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
    EXPECT_EQ(
        DisassembleProgram(buf.get(), len),
        (std::vector<std::string>{
            "0: data        0,",
            "3: debugbuf    size=3495",
            "7: lddw        r0, counter=7",
            "9: add         r0, 1",
            "11: stdw        counter=7, r0",
            "13: ldh         r0, [12]",
            "15: jlt         r0, 0x600, cnt_and_drop[cnt=33]",
            "20: jeq         r0, 0x88a2, cnt_and_drop[cnt=34]",
            "25: jeq         r0, 0x88a4, cnt_and_drop[cnt=34]",
            "30: jeq         r0, 0x88b8, cnt_and_drop[cnt=34]",
            "35: jeq         r0, 0x88cd, cnt_and_drop[cnt=34]",
            "40: jeq         r0, 0x88e1, cnt_and_drop[cnt=34]",
            "45: jeq         r0, 0x88e3, cnt_and_drop[cnt=34]",
            "50: jne         r0, 0x806, 106",
            "55: li          r0, 14",
            "57: jbsne       r0, (6), cnt_and_pass[cnt=15], 000108000604",
            "68: ldh         r0, [20]",
            "70: jeq         r0, 0x1, 97",
            "73: jne         r0, 0x2, cnt_and_pass[cnt=16]",
            "78: ldw         r0, [28]",
            "80: jeq         r0, 0x0, cnt_and_drop[cnt=35]",
            "85: li          r0, 0",
            "86: jbsne       r0, (6), cnt_and_pass[cnt=17], ffffffffffff",
            "97: ldw         r0, [38]",
            "99: jeq         r0, 0x0, cnt_and_drop[cnt=22]",
            "104: pass        counter=8",
            "106: ldh         r0, [12]",
            "108: jne         r0, 0x800, 183",
            "113: ldb         r0, [23]",
            "115: jne         r0, 0x11, 146",
            "118: ldh         r0, [20]",
            "120: jset        r0, 0x1fff, 146",
            "125: ldm         r1, m[13]",
            "127: ldhx        r0, [r1+16]",
            "129: jne         r0, 0x44, 146",
            "132: li          r0, 50",
            "134: add         r0, r1",
            "135: jbsne       r0, (6), 146, e212507c6345",
            "144: pass        counter=9",
            "146: ldb         r0, [30]",
            "148: and         r0, 0xf0",
            "151: jeq         r0, 0xe0, cnt_and_drop[cnt=27]",
            "156: ldw         r0, [30]",
            "158: jeq         r0, 0xffffffff, cnt_and_drop[cnt=25]",
            "167: li          r0, 0",
            "168: jbsne       r0, (6), cnt_and_pass[cnt=12], ffffffffffff",
            "179: drop        counter=24",
            "181: pass        counter=10",
            "183: jeq         r0, 0x86dd, 202",
            "188: li          r0, 0",
            "189: jbsne       r0, (6), cnt_and_pass[cnt=18], ffffffffffff",
            "200: drop        counter=20",
            "202: ldb         r0, [20]",
            "204: jeq         r0, 0x3a, 216",
            "207: ldb         r0, [38]",
            "209: jeq         r0, 0xff, cnt_and_drop[cnt=32]",
            "214: pass        counter=14",
            "216: ldb         r0, [54]",
            "218: jeq         r0, 0x85, cnt_and_drop[cnt=28]",
            "223: jne         r0, 0x88, 248",
            "226: li          r0, 38",
            "228: jbsne       r0, (15), 248, ff0200000000000000000000000000",
            "246: drop        counter=29",
            "248: ldm         r0, m[14]",
            "250: jne         r0, 0xa6, 459",
            "253: ldm         r0, m[15]",
            "255: jgt         r0, 0x254, 459",
            "260: li          r0, 0",
            "261: jbsne       r0, (15), 459, e212507c6345648788fd6df086dd68",
            "279: li          r0, 18",
            "281: jbsne       r0, (38), 459, "
            "00703afffe800000000000002a0079e10abc1539fe80000000000000e01250fffe7c63458600",
            "322: li          r0, 58",
            "324: jbsne       r0, (2), 459, 4000",
            "329: ldh         r0, [60]",
            "331: jlt         r0, 0x254, 459",
            "336: li          r0, 62",
            "338: jbsne       r0, (8), 459, 0000000000000000",
            "349: li          r0, 78",
            "351: jbsne       r0, (4), 459, 19050000",
            "358: ldw         r0, [82]",
            "360: jlt         r0, 0x254, 459",
            "365: li          r0, 86",
            "367: jbsne       r0, (32), 459, "
            "2001486048600000000000000000646420014860486000000000000000000064",
            "402: li          r0, 118",
            "404: jbsne       r0, (4), 459, 030440c0",
            "411: ldw         r0, [122]",
            "413: jlt         r0, 0x254, 459",
            "418: ldw         r0, [126]",
            "420: jlt         r0, 0x254, 459",
            "425: li          r0, 130",
            "428: jbsne       r0, (4), 459, 00000000",
            "435: li          r0, 134",
            "438: jbsne       r0, (16), 459, 2a0079e10abc15390000000000000000",
            "457: drop        counter=21",
            "459: pass        counter=13",
        }));
}

TEST(ApfGeneratorTest, testFullApfV4ProgramGenerationIPV4) {
    auto gen = AllocGen();
    ASSERT_NE(gen, nullptr);
    const apf_label lbl_94 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_109 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_151 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_204 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_225 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_241 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_275 = apf_gen_alloc_label(gen.get());
    apf_gen_add_lddw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_add(gen.get(), APF_REG_R0, 1);
    apf_gen_add_stdw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jlt(gen.get(), 0x600, apf_gen_cnt_drop_label(33));
    apf_gen_add_jeq(gen.get(), 0x88a2, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88a4, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88b8, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88cd, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88e1, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88e3, apf_gen_cnt_drop_label(34));
    apf_gen_add_jne(gen.get(), 0x806, lbl_109);
    apf_gen_add_li(gen.get(), APF_REG_R0, 14);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(15), "000108000604");
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x1, lbl_94);
    apf_gen_add_jne(gen.get(), 0x2, apf_gen_cnt_pass_label(16));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 28);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_drop_label(35));
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(17), "ffffffffffff");

    apf_gen_define_label(gen.get(), lbl_94);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), apf_gen_cnt_drop_label(23), "c0a801b3");
    apf_gen_add_cnt_and_pass(gen.get(), 8);

    apf_gen_define_label(gen.get(), lbl_109);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jne(gen.get(), 0x800, lbl_204);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
    apf_gen_add_jne(gen.get(), 0x11, lbl_151);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jset(gen.get(), 0x1fff, lbl_151);
    apf_gen_add_ldm(gen.get(), APF_REG_R1, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_ldhx(gen.get(), APF_REG_R0, 16);
    apf_gen_add_jne(gen.get(), 0x44, lbl_151);
    apf_gen_add_li(gen.get(), APF_REG_R0, 50);
    apf_gen_add_add_reg(gen.get(), APF_REG_R0);
    AddJbsneHex(gen.get(), lbl_151, "f683d58f832b");
    apf_gen_add_cnt_and_pass(gen.get(), 9);

    apf_gen_define_label(gen.get(), lbl_151);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 30);
    apf_gen_add_and(gen.get(), APF_REG_R0, 240);
    apf_gen_add_jeq(gen.get(), 0xe0, apf_gen_cnt_drop_label(27));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 30);
    apf_gen_add_jeq(gen.get(), 0xffffffffu, apf_gen_cnt_drop_label(25));
    apf_gen_add_jeq(gen.get(), 0xc0a801ffu, apf_gen_cnt_drop_label(26));
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(12), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 24);
    apf_gen_add_cnt_and_pass(gen.get(), 10);

    apf_gen_define_label(gen.get(), lbl_204);
    apf_gen_add_jeq(gen.get(), 0x86dd, lbl_225);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(18), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 20);

    apf_gen_define_label(gen.get(), lbl_225);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x3a, lbl_241);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 38);
    apf_gen_add_jeq(gen.get(), 0xff, apf_gen_cnt_drop_label(32));
    apf_gen_add_cnt_and_pass(gen.get(), 14);

    apf_gen_define_label(gen.get(), lbl_241);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 54);
    apf_gen_add_jeq(gen.get(), 0x85, apf_gen_cnt_drop_label(28));
    apf_gen_add_jne(gen.get(), 0x88, lbl_275);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), lbl_275, "ff0200000000000000000000000000");
    apf_gen_add_cnt_and_drop(gen.get(), 29);

    apf_gen_define_label(gen.get(), lbl_275);
    apf_gen_add_cnt_and_pass(gen.get(), 13);

    size_t len = 0;
    auto buf = GenerateProgram(gen.get(), &len);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
    EXPECT_EQ(
        DisassembleProgram(buf.get(), len),
        (std::vector<std::string>{
            "0: data        0,",
            "3: debugbuf    size=3713",
            "7: lddw        r0, counter=7",
            "9: add         r0, 1",
            "11: stdw        counter=7, r0",
            "13: ldh         r0, [12]",
            "15: jlt         r0, 0x600, cnt_and_drop[cnt=33]",
            "20: jeq         r0, 0x88a2, cnt_and_drop[cnt=34]",
            "25: jeq         r0, 0x88a4, cnt_and_drop[cnt=34]",
            "30: jeq         r0, 0x88b8, cnt_and_drop[cnt=34]",
            "35: jeq         r0, 0x88cd, cnt_and_drop[cnt=34]",
            "40: jeq         r0, 0x88e1, cnt_and_drop[cnt=34]",
            "45: jeq         r0, 0x88e3, cnt_and_drop[cnt=34]",
            "50: jne         r0, 0x806, 100",
            "55: li          r0, 14",
            "57: jbsne       r0, (6), cnt_and_pass[cnt=15], 000108000604",
            "66: ldh         r0, [20]",
            "68: jeq         r0, 0x1, 89",
            "71: jne         r0, 0x2, cnt_and_pass[cnt=16]",
            "74: ldw         r0, [28]",
            "76: jeq         r0, 0x0, cnt_and_drop[cnt=35]",
            "79: li          r0, 0",
            "80: jbsne       r0, (6), cnt_and_pass[cnt=17], ffffffffffff",
            "89: li          r0, 38",
            "91: jbsne       r0, (4), cnt_and_drop[cnt=23], c0a801b3",
            "98: pass        counter=8",
            "100: ldh         r0, [12]",
            "102: jne         r0, 0x800, 182",
            "107: ldb         r0, [23]",
            "109: jne         r0, 0x11, 140",
            "112: ldh         r0, [20]",
            "114: jset        r0, 0x1fff, 140",
            "119: ldm         r1, m[13]",
            "121: ldhx        r0, [r1+16]",
            "123: jne         r0, 0x44, 140",
            "126: li          r0, 50",
            "128: add         r0, r1",
            "129: jbsne       r0, (6), 140, f683d58f832b",
            "138: pass        counter=9",
            "140: ldb         r0, [30]",
            "142: and         r0, 0xf0",
            "145: jeq         r0, 0xe0, cnt_and_drop[cnt=27]",
            "148: ldw         r0, [30]",
            "150: jeq         r0, 0xffffffff, cnt_and_drop[cnt=25]",
            "159: jeq         r0, 0xc0a801ff, cnt_and_drop[cnt=26]",
            "168: li          r0, 0",
            "169: jbsne       r0, (6), cnt_and_pass[cnt=12], ffffffffffff",
            "178: drop        counter=24",
            "180: pass        counter=10",
            "182: jeq         r0, 0x86dd, 199",
            "187: li          r0, 0",
            "188: jbsne       r0, (6), cnt_and_pass[cnt=18], ffffffffffff",
            "197: drop        counter=20",
            "199: ldb         r0, [20]",
            "201: jeq         r0, 0x3a, 211",
            "204: ldb         r0, [38]",
            "206: jeq         r0, 0xff, cnt_and_drop[cnt=32]",
            "209: pass        counter=14",
            "211: ldb         r0, [54]",
            "213: jeq         r0, 0x85, cnt_and_drop[cnt=28]",
            "216: jne         r0, 0x88, 241",
            "219: li          r0, 38",
            "221: jbsne       r0, (15), 241, ff0200000000000000000000000000",
            "239: drop        counter=29",
            "241: pass        counter=13",
        }));
}

TEST(ApfGeneratorTest, testFullApfV4ProgramGenerationNatTKeepAliveV4) {
    auto gen = AllocGen();
    ASSERT_NE(gen, nullptr);
    const apf_label lbl_100 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_115 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_157 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_243 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_263 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_284 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_303 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_337 = apf_gen_alloc_label(gen.get());
    apf_gen_add_lddw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_add(gen.get(), APF_REG_R0, 1);
    apf_gen_add_stdw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jlt(gen.get(), 0x600, apf_gen_cnt_drop_label(33));
    apf_gen_add_jeq(gen.get(), 0x88a2, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88a4, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88b8, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88cd, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88e1, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88e3, apf_gen_cnt_drop_label(34));
    apf_gen_add_jne(gen.get(), 0x806, lbl_115);
    apf_gen_add_li(gen.get(), APF_REG_R0, 14);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(15), "000108000604");
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x1, lbl_100);
    apf_gen_add_jne(gen.get(), 0x2, apf_gen_cnt_pass_label(16));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 28);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_drop_label(35));
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(17), "ffffffffffff");

    apf_gen_define_label(gen.get(), lbl_100);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), apf_gen_cnt_drop_label(23), "c0a801be");
    apf_gen_add_cnt_and_pass(gen.get(), 8);

    apf_gen_define_label(gen.get(), lbl_115);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jne(gen.get(), 0x800, lbl_263);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
    apf_gen_add_jne(gen.get(), 0x11, lbl_157);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jset(gen.get(), 0x1fff, lbl_157);
    apf_gen_add_ldm(gen.get(), APF_REG_R1, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_ldhx(gen.get(), APF_REG_R0, 16);
    apf_gen_add_jne(gen.get(), 0x44, lbl_157);
    apf_gen_add_li(gen.get(), APF_REG_R0, 50);
    apf_gen_add_add_reg(gen.get(), APF_REG_R0);
    AddJbsneHex(gen.get(), lbl_157, "ea42226789c0");
    apf_gen_add_cnt_and_pass(gen.get(), 9);

    apf_gen_define_label(gen.get(), lbl_157);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 30);
    apf_gen_add_and(gen.get(), APF_REG_R0, 240);
    apf_gen_add_jeq(gen.get(), 0xe0, apf_gen_cnt_drop_label(27));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 30);
    apf_gen_add_jeq(gen.get(), 0xffffffffu, apf_gen_cnt_drop_label(25));
    apf_gen_add_jeq(gen.get(), 0xc0a801ffu, apf_gen_cnt_drop_label(26));
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
    apf_gen_add_jne(gen.get(), 0x11, lbl_243);
    apf_gen_add_li(gen.get(), APF_REG_R0, 26);
    AddJbsneHex(gen.get(), lbl_243, "6b7a1f1fc0a801be");
    apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_add(gen.get(), APF_REG_R0, 8);
    apf_gen_add_swap(gen.get());
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 16);
    apf_gen_add_neg(gen.get(), APF_REG_R1);
    apf_gen_add_add_reg(gen.get(), APF_REG_R0);
    apf_gen_add_jne(gen.get(), 0x1, lbl_243);
    apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_add(gen.get(), APF_REG_R0, 14);
    AddJbsneHex(gen.get(), lbl_243, "1194ceca");
    apf_gen_add_add(gen.get(), APF_REG_R0, 8);
    AddJbsneHex(gen.get(), lbl_243, "ff");
    apf_gen_add_cnt_and_drop(gen.get(), 38);

    apf_gen_define_label(gen.get(), lbl_243);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(12), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 24);
    apf_gen_add_cnt_and_pass(gen.get(), 10);

    apf_gen_define_label(gen.get(), lbl_263);
    apf_gen_add_jeq(gen.get(), 0x86dd, lbl_284);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(18), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 20);

    apf_gen_define_label(gen.get(), lbl_284);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_pass_label(12));
    apf_gen_add_jeq(gen.get(), 0x3a, lbl_303);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 38);
    apf_gen_add_jeq(gen.get(), 0xff, apf_gen_cnt_drop_label(32));
    apf_gen_add_cnt_and_pass(gen.get(), 14);

    apf_gen_define_label(gen.get(), lbl_303);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 54);
    apf_gen_add_jeq(gen.get(), 0x85, apf_gen_cnt_drop_label(28));
    apf_gen_add_jne(gen.get(), 0x88, lbl_337);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), lbl_337, "ff0200000000000000000000000000");
    apf_gen_add_cnt_and_drop(gen.get(), 29);

    apf_gen_define_label(gen.get(), lbl_337);
    apf_gen_add_cnt_and_pass(gen.get(), 13);

    size_t len = 0;
    auto buf = GenerateProgram(gen.get(), &len);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
    EXPECT_EQ(
        DisassembleProgram(buf.get(), len),
        (std::vector<std::string>{
            "0: data        0,",
            "3: debugbuf    size=3641",
            "7: lddw        r0, counter=7",
            "9: add         r0, 1",
            "11: stdw        counter=7, r0",
            "13: ldh         r0, [12]",
            "15: jlt         r0, 0x600, cnt_and_drop[cnt=33]",
            "20: jeq         r0, 0x88a2, cnt_and_drop[cnt=34]",
            "25: jeq         r0, 0x88a4, cnt_and_drop[cnt=34]",
            "30: jeq         r0, 0x88b8, cnt_and_drop[cnt=34]",
            "35: jeq         r0, 0x88cd, cnt_and_drop[cnt=34]",
            "40: jeq         r0, 0x88e1, cnt_and_drop[cnt=34]",
            "45: jeq         r0, 0x88e3, cnt_and_drop[cnt=34]",
            "50: jne         r0, 0x806, 106",
            "55: li          r0, 14",
            "57: jbsne       r0, (6), cnt_and_pass[cnt=15], 000108000604",
            "68: ldh         r0, [20]",
            "70: jeq         r0, 0x1, 95",
            "73: jne         r0, 0x2, cnt_and_pass[cnt=16]",
            "78: ldw         r0, [28]",
            "80: jeq         r0, 0x0, cnt_and_drop[cnt=35]",
            "85: li          r0, 0",
            "86: jbsne       r0, (6), cnt_and_pass[cnt=17], ffffffffffff",
            "95: li          r0, 38",
            "97: jbsne       r0, (4), cnt_and_drop[cnt=23], c0a801be",
            "104: pass        counter=8",
            "106: ldh         r0, [12]",
            "108: jne         r0, 0x800, 239",
            "113: ldb         r0, [23]",
            "115: jne         r0, 0x11, 146",
            "118: ldh         r0, [20]",
            "120: jset        r0, 0x1fff, 146",
            "125: ldm         r1, m[13]",
            "127: ldhx        r0, [r1+16]",
            "129: jne         r0, 0x44, 146",
            "132: li          r0, 50",
            "134: add         r0, r1",
            "135: jbsne       r0, (6), 146, ea42226789c0",
            "144: pass        counter=9",
            "146: ldb         r0, [30]",
            "148: and         r0, 0xf0",
            "151: jeq         r0, 0xe0, cnt_and_drop[cnt=27]",
            "154: ldw         r0, [30]",
            "156: jeq         r0, 0xffffffff, cnt_and_drop[cnt=25]",
            "165: jeq         r0, 0xc0a801ff, cnt_and_drop[cnt=26]",
            "174: ldb         r0, [23]",
            "176: jne         r0, 0x11, 225",
            "179: li          r0, 26",
            "181: jbsne       r0, (8), 225, 6b7a1f1fc0a801be",
            "192: ldm         r0, m[13]",
            "194: add         r0, 8",
            "196: swap",
            "198: ldh         r0, [16]",
            "200: neg         r1",
            "202: add         r0, r1",
            "203: jne         r0, 0x1, 225",
            "206: ldm         r0, m[13]",
            "208: add         r0, 14",
            "210: jbsne       r0, (4), 225, 1194ceca",
            "217: add         r0, 8",
            "219: jbsne       r0, (1), 225, ff",
            "223: drop        counter=38",
            "225: li          r0, 0",
            "226: jbsne       r0, (6), cnt_and_pass[cnt=12], ffffffffffff",
            "235: drop        counter=24",
            "237: pass        counter=10",
            "239: jeq         r0, 0x86dd, 256",
            "244: li          r0, 0",
            "245: jbsne       r0, (6), cnt_and_pass[cnt=18], ffffffffffff",
            "254: drop        counter=20",
            "256: ldb         r0, [20]",
            "258: jeq         r0, 0x0, cnt_and_pass[cnt=12]",
            "261: jeq         r0, 0x3a, 271",
            "264: ldb         r0, [38]",
            "266: jeq         r0, 0xff, cnt_and_drop[cnt=32]",
            "269: pass        counter=14",
            "271: ldb         r0, [54]",
            "273: jeq         r0, 0x85, cnt_and_drop[cnt=28]",
            "276: jne         r0, 0x88, 301",
            "279: li          r0, 38",
            "281: jbsne       r0, (15), 301, ff0200000000000000000000000000",
            "299: drop        counter=29",
            "301: pass        counter=13",
        }));
}

TEST(ApfGeneratorTest, testInfiniteLifetimeFullApfV4ProgramGeneration) {
    auto gen = AllocGen();
    ASSERT_NE(gen, nullptr);
    const apf_label lbl_104 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_122 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_165 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_225 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_249 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_273 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_297 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_333 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_421 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_480 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_547 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_574 = apf_gen_alloc_label(gen.get());
    apf_gen_add_lddw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_add(gen.get(), APF_REG_R0, 1);
    apf_gen_add_stdw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jlt(gen.get(), 0x600, apf_gen_cnt_drop_label(35));
    apf_gen_add_jeq(gen.get(), 0x88a2, apf_gen_cnt_drop_label(36));
    apf_gen_add_jeq(gen.get(), 0x88a4, apf_gen_cnt_drop_label(36));
    apf_gen_add_jeq(gen.get(), 0x88b8, apf_gen_cnt_drop_label(36));
    apf_gen_add_jeq(gen.get(), 0x88cd, apf_gen_cnt_drop_label(36));
    apf_gen_add_jeq(gen.get(), 0x88e1, apf_gen_cnt_drop_label(36));
    apf_gen_add_jeq(gen.get(), 0x88e3, apf_gen_cnt_drop_label(36));
    apf_gen_add_jne(gen.get(), 0x806, lbl_122);
    apf_gen_add_li(gen.get(), APF_REG_R0, 14);
    AddJbsneHex(gen.get(), apf_gen_cnt_drop_label(43), "000108000604");
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x1, lbl_104);
    apf_gen_add_jne(gen.get(), 0x2, apf_gen_cnt_drop_label(44));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 28);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_drop_label(37));
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(19), "ffffffffffff");

    apf_gen_define_label(gen.get(), lbl_104);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), apf_gen_cnt_drop_label(25), "c0a801ec");
    apf_gen_add_cnt_and_pass(gen.get(), 10);

    apf_gen_define_label(gen.get(), lbl_122);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jne(gen.get(), 0x800, lbl_249);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
    apf_gen_add_jne(gen.get(), 0x11, lbl_165);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jset(gen.get(), 0x1fff, lbl_165);
    apf_gen_add_ldm(gen.get(), APF_REG_R1, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_ldhx(gen.get(), APF_REG_R0, 16);
    apf_gen_add_jne(gen.get(), 0x44, lbl_165);
    apf_gen_add_li(gen.get(), APF_REG_R0, 50);
    apf_gen_add_add_reg(gen.get(), APF_REG_R0);
    AddJbsneHex(gen.get(), lbl_165, "7e9046bc7008");
    apf_gen_add_cnt_and_pass(gen.get(), 11);

    apf_gen_define_label(gen.get(), lbl_165);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 30);
    apf_gen_add_and(gen.get(), APF_REG_R0, 240);
    apf_gen_add_jeq(gen.get(), 0xe0, apf_gen_cnt_drop_label(29));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 30);
    apf_gen_add_jeq(gen.get(), 0xffffffffu, apf_gen_cnt_drop_label(27));
    apf_gen_add_jeq(gen.get(), 0xc0a801ffu, apf_gen_cnt_drop_label(28));
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
    apf_gen_add_jne(gen.get(), 0x6, lbl_225);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jset(gen.get(), 0x1fff, lbl_225);
    apf_gen_add_ldm(gen.get(), APF_REG_R1, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_ldhx(gen.get(), APF_REG_R0, 16);
    apf_gen_add_jne(gen.get(), 0x7, lbl_225);
    apf_gen_add_cnt_and_drop(gen.get(), 42);

    apf_gen_define_label(gen.get(), lbl_225);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(14), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 26);
    apf_gen_add_cnt_and_pass(gen.get(), 12);

    apf_gen_define_label(gen.get(), lbl_249);
    apf_gen_add_jeq(gen.get(), 0x86dd, lbl_273);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(20), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 22);

    apf_gen_define_label(gen.get(), lbl_273);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_pass_label(14));
    apf_gen_add_jeq(gen.get(), 0x3a, lbl_297);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 38);
    apf_gen_add_jeq(gen.get(), 0xff, apf_gen_cnt_drop_label(34));
    apf_gen_add_cnt_and_pass(gen.get(), 16);

    apf_gen_define_label(gen.get(), lbl_297);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 54);
    apf_gen_add_jeq(gen.get(), 0x85, apf_gen_cnt_drop_label(30));
    apf_gen_add_jne(gen.get(), 0x88, lbl_333);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), lbl_333, "ff0200000000000000000000000000");
    apf_gen_add_cnt_and_drop(gen.get(), 31);

    apf_gen_define_label(gen.get(), lbl_333);
    apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_PACKET_SIZE);
    apf_gen_add_jne(gen.get(), 0x96, lbl_574);
    apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_FILTER_AGE);
    apf_gen_add_jgt(gen.get(), 0x48e, lbl_574);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), lbl_574, "7e9046bc700828c68e23672c86dd60");
    apf_gen_add_li(gen.get(), APF_REG_R0, 18);
    AddJbsneHex(gen.get(), lbl_574, "00603afffe800000000000002ac68efffe23672c");
    apf_gen_add_li(gen.get(), APF_REG_R0, 54);
    AddJbsneHex(gen.get(), lbl_574, "8600");
    apf_gen_add_li(gen.get(), APF_REG_R0, 58);
    AddJbsneHex(gen.get(), lbl_574, "40c0");
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 60);
    apf_gen_add_jeq(gen.get(), 0x0, lbl_574);
    apf_gen_add_jlt(gen.get(), 0xb4, lbl_421);
    apf_gen_add_jlt(gen.get(), 0x91e, lbl_574);
    apf_gen_add_jgt(gen.get(), 0x1b58, lbl_574);

    apf_gen_define_label(gen.get(), lbl_421);
    apf_gen_add_li(gen.get(), APF_REG_R0, 62);
    AddJbsneHex(gen.get(), lbl_574,
                "0000000000000000010128c68e23672c05010000000005dc030440c0");
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 90);
    apf_gen_add_jeq(gen.get(), 0x0, lbl_574);
    apf_gen_add_jlt(gen.get(), 0xb4, lbl_480);
    apf_gen_add_jlt(gen.get(), 0x55555555u, lbl_574);
    apf_gen_add_jgt(gen.get(), 0xffffffffu, lbl_574);

    apf_gen_define_label(gen.get(), lbl_480);
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 94);
    apf_gen_add_jlt(gen.get(), 0x55555555u, lbl_574);
    apf_gen_add_jgt(gen.get(), 0xffffffffu, lbl_574);
    apf_gen_add_li(gen.get(), APF_REG_R0, 98);
    AddJbsneHex(gen.get(), lbl_574, "000000002401fa000480f000000000000000000019030000");
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 122);
    apf_gen_add_jeq(gen.get(), 0x0, lbl_574);
    apf_gen_add_jlt(gen.get(), 0x78, lbl_547);
    apf_gen_add_jlt(gen.get(), 0x91e, lbl_574);
    apf_gen_add_jgt(gen.get(), 0x1b58, lbl_574);

    apf_gen_define_label(gen.get(), lbl_547);
    apf_gen_add_li(gen.get(), APF_REG_R0, 126);
    AddJbsneHex(gen.get(), lbl_574, "2401fa000480f00000000000000000010701");
    apf_gen_add_cnt_and_drop(gen.get(), 23);

    apf_gen_define_label(gen.get(), lbl_574);
    apf_gen_add_cnt_and_pass(gen.get(), 15);

    size_t len = 0;
    auto buf = GenerateProgram(gen.get(), &len);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
    EXPECT_EQ(
        DisassembleProgram(buf.get(), len),
        (std::vector<std::string>{
            "0: data        0,",
            "3: debugbuf    size=3392",
            "7: lddw        r0, counter=7",
            "9: add         r0, 1",
            "11: stdw        counter=7, r0",
            "13: ldh         r0, [12]",
            "15: jlt         r0, 0x600, cnt_and_drop[cnt=35]",
            "20: jeq         r0, 0x88a2, cnt_and_drop[cnt=36]",
            "25: jeq         r0, 0x88a4, cnt_and_drop[cnt=36]",
            "30: jeq         r0, 0x88b8, cnt_and_drop[cnt=36]",
            "35: jeq         r0, 0x88cd, cnt_and_drop[cnt=36]",
            "40: jeq         r0, 0x88e1, cnt_and_drop[cnt=36]",
            "45: jeq         r0, 0x88e3, cnt_and_drop[cnt=36]",
            "50: jne         r0, 0x806, 110",
            "55: li          r0, 14",
            "57: jbsne       r0, (6), cnt_and_drop[cnt=43], 000108000604",
            "68: ldh         r0, [20]",
            "70: jeq         r0, 0x1, 97",
            "73: jne         r0, 0x2, cnt_and_drop[cnt=44]",
            "78: ldw         r0, [28]",
            "80: jeq         r0, 0x0, cnt_and_drop[cnt=37]",
            "85: li          r0, 0",
            "86: jbsne       r0, (6), cnt_and_pass[cnt=19], ffffffffffff",
            "97: li          r0, 38",
            "99: jbsne       r0, (4), cnt_and_drop[cnt=25], c0a801ec",
            "108: pass        counter=10",
            "110: ldh         r0, [12]",
            "112: jne         r0, 0x800, 217",
            "117: ldb         r0, [23]",
            "119: jne         r0, 0x11, 150",
            "122: ldh         r0, [20]",
            "124: jset        r0, 0x1fff, 150",
            "129: ldm         r1, m[13]",
            "131: ldhx        r0, [r1+16]",
            "133: jne         r0, 0x44, 150",
            "136: li          r0, 50",
            "138: add         r0, r1",
            "139: jbsne       r0, (6), 150, 7e9046bc7008",
            "148: pass        counter=11",
            "150: ldb         r0, [30]",
            "152: and         r0, 0xf0",
            "155: jeq         r0, 0xe0, cnt_and_drop[cnt=29]",
            "160: ldw         r0, [30]",
            "162: jeq         r0, 0xffffffff, cnt_and_drop[cnt=27]",
            "171: jeq         r0, 0xc0a801ff, cnt_and_drop[cnt=28]",
            "180: ldb         r0, [23]",
            "182: jne         r0, 0x6, 201",
            "185: ldh         r0, [20]",
            "187: jset        r0, 0x1fff, 201",
            "192: ldm         r1, m[13]",
            "194: ldhx        r0, [r1+16]",
            "196: jne         r0, 0x7, 201",
            "199: drop        counter=42",
            "201: li          r0, 0",
            "202: jbsne       r0, (6), cnt_and_pass[cnt=14], ffffffffffff",
            "213: drop        counter=26",
            "215: pass        counter=12",
            "217: jeq         r0, 0x86dd, 236",
            "222: li          r0, 0",
            "223: jbsne       r0, (6), cnt_and_pass[cnt=20], ffffffffffff",
            "234: drop        counter=22",
            "236: ldb         r0, [20]",
            "238: jeq         r0, 0x0, cnt_and_pass[cnt=14]",
            "243: jeq         r0, 0x3a, 255",
            "246: ldb         r0, [38]",
            "248: jeq         r0, 0xff, cnt_and_drop[cnt=34]",
            "253: pass        counter=16",
            "255: ldb         r0, [54]",
            "257: jeq         r0, 0x85, cnt_and_drop[cnt=30]",
            "262: jne         r0, 0x88, 287",
            "265: li          r0, 38",
            "267: jbsne       r0, (15), 287, ff0200000000000000000000000000",
            "285: drop        counter=31",
            "287: ldm         r0, m[14]",
            "289: jne         r0, 0x96, 526",
            "292: ldm         r0, m[15]",
            "294: jgt         r0, 0x48e, 526",
            "299: li          r0, 0",
            "300: jbsne       r0, (15), 526, 7e9046bc700828c68e23672c86dd60",
            "318: li          r0, 18",
            "320: jbsne       r0, (20), 526, 00603afffe800000000000002ac68efffe23672c",
            "343: li          r0, 54",
            "345: jbsne       r0, (2), 526, 8600",
            "350: li          r0, 58",
            "352: jbsne       r0, (2), 526, 40c0",
            "357: ldh         r0, [60]",
            "359: jeq         r0, 0x0, 526",
            "362: jlt         r0, 0xb4, 375",
            "365: jlt         r0, 0x91e, 526",
            "370: jgt         r0, 0x1b58, 526",
            "375: li          r0, 62",
            "377: jbsne       r0, (28), 526, "
            "0000000000000000010128c68e23672c05010000000005dc030440c0",
            "408: ldw         r0, [90]",
            "410: jeq         r0, 0x0, 526",
            "413: jlt         r0, 0xb4, 434",
            "416: jlt         r0, 0x55555555, 526",
            "425: jgt         r0, 0xffffffff, 526",
            "434: ldw         r0, [94]",
            "436: jlt         r0, 0x55555555, 526",
            "445: jgt         r0, 0xffffffff, 526",
            "454: li          r0, 98",
            "456: jbsne       r0, (24), 526, 000000002401fa000480f000000000000000000019030000",
            "483: ldw         r0, [122]",
            "485: jeq         r0, 0x0, 526",
            "488: jlt         r0, 0x78, 501",
            "491: jlt         r0, 0x91e, 526",
            "496: jgt         r0, 0x1b58, 526",
            "501: li          r0, 126",
            "503: jbsne       r0, (18), 526, 2401fa000480f00000000000000000010701",
            "524: drop        counter=23",
            "526: pass        counter=15",
        }));
}

TEST(ApfGeneratorTest, testBoundaryWidthsAndStickyErrorLatching) {
    // 1. Signed vs. unsigned boundary immediate widths and shared branch field width
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R0, -128);    // 1-byte signed (2 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, -129);    // 2-byte signed (3 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, 127);     // 1-byte signed (2 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, 128);     // 2-byte signed (3 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, -32768);  // 2-byte signed (3 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, -32769);  // 4-byte signed (5 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, 32767);   // 2-byte signed (3 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, 32768);   // 4-byte signed (5 bytes total)
        apf_gen_add_ldb(gen.get(), APF_REG_R0, 255);    // 1-byte unsigned (2 bytes total)
        apf_gen_add_ldb(gen.get(), APF_REG_R0, 256);    // 2-byte unsigned (3 bytes total)
        apf_gen_add_ldb(gen.get(), APF_REG_R0, 65535);  // 2-byte unsigned (3 bytes total)
        apf_gen_add_ldb(gen.get(), APF_REG_R0, 65536);  // 4-byte unsigned (5 bytes total)
        apf_gen_add_mul(gen.get(), APF_REG_R0, 0);      // 1-byte non-zero-imm (2 bytes total)
        apf_gen_add_div(gen.get(), APF_REG_R0, 2);      // 1-byte non-zero-imm (2 bytes total)
        apf_gen_add_or(gen.get(), APF_REG_R0, 0x100);   // 2-byte unsigned (3 bytes total)
        // Shared branch width: target=cnt_pass(128) (2 bytes), imm=1 -> field_len=2 (5 bytes)
        apf_gen_add_jeq(gen.get(), 1, apf_gen_cnt_pass_label(128));
        // Shared branch width: target=DROP (1 byte), imm=0x12345678 -> field_len=4 (9 bytes)
        apf_gen_add_jne(gen.get(), 0x12345678, APF_LABEL_DROP);
        // 2-byte unconditional jump target
        apf_gen_add_jmp(gen.get(), apf_gen_cnt_pass_label(1000));

        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        EXPECT_EQ(len, 70u);
        EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
        EXPECT_EQ(
            DisassembleProgram(buf.get(), len),
            (std::vector<std::string>{
                "0: data        0,",
                "3: debugbuf    size=26",
                "7: li          r0, -128",
                "9: li          r0, -129",
                "12: li          r0, 127",
                "14: li          r0, 128",
                "17: li          r0, -32768",
                "20: li          r0, -32769",
                "25: li          r0, 32767",
                "28: li          r0, 32768",
                "33: ldb         r0, [255]",
                "35: ldb         r0, [256]",
                "38: ldb         r0, [65535]",
                "41: ldb         r0, [65536]",
                "46: mul         r0, 0",
                "48: div         r0, 2",
                "50: or          r0, 0x100",
                "53: jeq         r0, 0x1, cnt_and_pass[cnt=128]",
                "58: jne         r0, 0x12345678, DROP",
                "67: jmp         cnt_and_pass[cnt=1000]",
            }));
    }

    // 2. 4-byte branch target (> 65535 bytes forward jump)
    {
        auto gen = AllocGen(APF_VERSION_61, 131072);
        ASSERT_NE(gen, nullptr);
        const std::vector<uint8_t> chunk(2047, 0x11);
        apf_gen_add_jmp(gen.get(), APF_LABEL_PASS);
        for (int i = 0; i < 33; i++) {
            apf_gen_add_jbsne(gen.get(), APF_LABEL_DROP, chunk.data(), 2047);
        }
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        // Leading jmp (at offset 7 after prologue) must use 4-byte target encoding (size_field = 3)
        EXPECT_EQ(buf.get()[7], (14u << 3) | (3u << 1) | 0u);
        EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
    }

    // 3. Sticky error latching and NULL pointer argument guards
    {
        size_t len = 123;
        EXPECT_EQ(apf_gen_generate(nullptr, nullptr, 0, &len), -1);
        EXPECT_EQ(len, 0u);
        EXPECT_EQ(apf_gen_add_pass(nullptr), -1);
        EXPECT_EQ(apf_gen_get_insn_count(nullptr), 0u);
        EXPECT_EQ(apf_gen_get_program_len(nullptr), 0u);
        size_t err_idx = 42;
        EXPECT_EQ(apf_gen_get_error(nullptr, &err_idx), APF_GEN_ERR_INVALID_ARGUMENT);
        EXPECT_EQ(err_idx, 0u);

        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        EXPECT_EQ(apf_gen_get_error(gen.get(), &err_idx), APF_GEN_OK);
        EXPECT_EQ(apf_gen_add_pass(gen.get()), 0);
        // Trigger a single invalid instruction call (divide by zero) at user instruction index 1
        EXPECT_EQ(apf_gen_add_div(gen.get(), APF_REG_R0, 0), -1);
        // Subsequent valid instruction calls still succeed, but apf_gen_generate() fails
        // because the generator's error state is sticky.
        EXPECT_EQ(apf_gen_add_pass(gen.get()), 0);
        EXPECT_EQ(GenerateProgram(gen.get(), &len), nullptr);
        EXPECT_EQ(apf_gen_get_error(gen.get(), &err_idx), APF_GEN_ERR_INVALID_ARGUMENT);
        EXPECT_EQ(err_idx, 1u);
    }

    // 4. 4-byte backward jump encoding (32-bit unsigned wraparound)
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_label lbl = apf_gen_alloc_label(gen.get());
        ASSERT_NE(lbl.id, APF_LABEL_INVALID.id);
        apf_gen_define_label(gen.get(), lbl);
        apf_gen_add_pass(gen.get());
        apf_gen_add_jmp(gen.get(), lbl);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 13u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4059",
                      "7: pass",
                      "8: jmp         7",
                  }));
    }
}

TEST(ApfGeneratorTest, testRamModelErrorReportingAndCallerBuffer) {
    // 1. RAM size validation at allocation: ram_len >= 1024, ram_len % 4 == 0, ram_len < 2 GiB
    EXPECT_EQ(AllocGen(APF_VERSION_61, 0), nullptr);
    EXPECT_EQ(AllocGen(APF_VERSION_61, 512), nullptr);
    EXPECT_EQ(AllocGen(APF_VERSION_61, 1020), nullptr);
    EXPECT_EQ(AllocGen(APF_VERSION_61, 1025), nullptr);
    EXPECT_EQ(AllocGen(APF_VERSION_61, 1026), nullptr);
    EXPECT_EQ(AllocGen(APF_VERSION_61, 0x80000000u), nullptr);

    // 2. Counter beyond RAM (4 * 300 = 1200 > 1024)
    {
        auto gen = AllocGen(APF_VERSION_61, 1024);
        ASSERT_NE(gen, nullptr);
        EXPECT_EQ(apf_gen_add_jmp(gen.get(), apf_gen_cnt_drop_label(300)), 0);
        size_t len = 0;
        EXPECT_EQ(GenerateProgram(gen.get(), &len), nullptr);
        EXPECT_EQ(apf_gen_get_error(gen.get(), nullptr), APF_GEN_ERR_RAM_OVERFLOW);
    }

    // 3. Counter inside program (710-byte program + 4 * 100 = 1110 > 1024)
    {
        auto gen = AllocGen(APF_VERSION_61, 1024);
        ASSERT_NE(gen, nullptr);
        const std::vector<uint8_t> payload(696, 0xAA);
        EXPECT_EQ(apf_gen_add_jbsne(gen.get(), APF_LABEL_PASS, payload.data(),
                                    static_cast<uint16_t>(payload.size())),
                  0);
        EXPECT_EQ(apf_gen_add_cnt_and_drop(gen.get(), 100), 0);
        size_t len = 0;
        EXPECT_EQ(GenerateProgram(gen.get(), &len), nullptr);
        EXPECT_EQ(apf_gen_get_error(gen.get(), nullptr), APF_GEN_ERR_RAM_OVERFLOW);
    }

    // 4. Program colliding with 6 system counters (program_len + 24 > 1024)
    {
        auto gen = AllocGen(APF_VERSION_61, 1024);
        ASSERT_NE(gen, nullptr);
        const std::vector<uint8_t> payload(995, 0xBB);
        EXPECT_EQ(apf_gen_add_jbsne(gen.get(), APF_LABEL_PASS, payload.data(),
                                    static_cast<uint16_t>(payload.size())),
                  0);
        size_t len = 0;
        EXPECT_EQ(GenerateProgram(gen.get(), &len), nullptr);
        EXPECT_EQ(apf_gen_get_error(gen.get(), nullptr), APF_GEN_ERR_RAM_OVERFLOW);
    }

    // 5. Caller buffer too small (recoverable retry) and forbidding mutations after generate()
    {
        auto gen = AllocGen(APF_VERSION_61, 1024);
        ASSERT_NE(gen, nullptr);
        EXPECT_EQ(apf_gen_add_pass(gen.get()), 0);
        size_t out_len = 0;
        EXPECT_EQ(apf_gen_generate(gen.get(), nullptr, 0, &out_len), 0);
        EXPECT_EQ(out_len, 8u);
        uint8_t out_buf[8];
        EXPECT_EQ(apf_gen_generate(gen.get(), out_buf, sizeof(out_buf), &out_len), 0);
        EXPECT_EQ(out_len, 8u);

        // Adding instructions or labels after the program has been written is forbidden
        EXPECT_EQ(apf_gen_add_div(gen.get(), APF_REG_R0, 0), -1);
        EXPECT_EQ(apf_gen_add_drop(gen.get()), -1);
        EXPECT_EQ(apf_gen_alloc_label(gen.get()).id, APF_LABEL_INVALID.id);
        EXPECT_EQ(apf_gen_get_error(gen.get(), nullptr), APF_GEN_ERR_ALREADY_GENERATED);

        auto gen2 = AllocGen(APF_VERSION_61, 1024);
        ASSERT_NE(gen2, nullptr);
        const uint8_t data[4] = {0x11, 0x22, 0x33, 0x44};
        EXPECT_EQ(apf_gen_set_data(gen2.get(), data, sizeof(data)), 0);
        EXPECT_EQ(apf_gen_add_pass(gen2.get()), 0);
        uint8_t small_buf[4];
        size_t len2 = 0;
        EXPECT_EQ(apf_gen_generate(gen2.get(), small_buf, sizeof(small_buf), &len2), -1);
        EXPECT_EQ(len2, 12u);
        EXPECT_EQ(apf_gen_get_error(gen2.get(), nullptr), APF_GEN_OK);

        std::vector<uint8_t> retry_buf(len2);
        EXPECT_EQ(apf_gen_generate(gen2.get(), retry_buf.data(), retry_buf.size(), &len2), 0);
        EXPECT_EQ(len2, 12u);
        EXPECT_EQ(DisassembleProgram(retry_buf.data(), len2),
                  (std::vector<std::string>{
                      "0: data        4, 11223344",
                      "7: debugbuf    size=988",
                      "11: pass",
                  }));
    }
}
