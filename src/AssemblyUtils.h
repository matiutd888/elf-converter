//
// Created by mateusz on 26.03.23.
//

#ifndef CONVERTERPROJECT_ASSEMBLYUTILS_H
#define CONVERTERPROJECT_ASSEMBLYUTILS_H


#include "utils.h"
#include <capstone/x86.h>
#include <map>
#include <string>

using reg_t = std::string;

namespace assemblyUtils {
    const int ARM_INSTRUCTION_SIZE_BYTES = 32;

    namespace {

        std::string tmp[2] = {"12", "13"};
        std::string memPrefix[2][2] = {{"w", "x"}, {"e", "r"}};

        const std::map<std::string, std::string> registerMaps64 = {
                {"rdi", "x0"},
                {"rsi", "x1"},
                {"rdx", "x2"},
                {"rcx", "x3"},
                {"r8", "x4"},
                {"r9", "x5"},
                {"rax", "x9"},
                {"r10", "x10"},
                {"r11", "x11"},
                {"rbp", "x29"},
                {"rbx", "x19"},
                {"r12", "x20"},
                {"r13", "x21"},
                {"r14", "x22"},
                {"r15", "x23"},
                {"rsp", "sp"},
        };
        const std::map<std::string, std::string> registerMaps32 = {
                {"edi", "w0"},
                {"esi", "w1"},
                {"edx", "w2"},
                {"ecx", "w3"},
                {"e8", "w4"},
                {"e9", "w5"},
                {"eax", "w9"},
                {"e10", "w10"},
                {"e11", "w11"},
                {"ebp", "w29"},
                {"ebx", "w19"},
                {"e12", "w20"},
                {"e13", "w21"},
                {"e14", "w22"},
                {"e15", "w23"},
                {"esp", "sp"},
        };
    }// namespace

    enum Arch { Aarch64 = 0,
                X86_64 = 1 };

    enum MemSize { MEM32 = 0,
                   MEM64 = 1 };

    enum TmpKind {
        TMP1 = 0,
        TMP2 = 1,
    };

    // Works for Arm and x86
    reg_t convertRegisterMemSize(Arch arch, MemSize memSize, const reg_t &r) {
        std::string suffix = r.substr(1);
        reg_t r64 = memPrefix[arch][memSize] + suffix;
        return r64;
    }
    //    bool isRegister(std::string s) {
    //        return registerMaps32.find(s) != registerMaps32.end() ||
    //        registerMaps64.find(s) != registerMaps64.end();
    //    }
    //
    //    bool isMem(std::string operand) {
    //        return operand.find("[")  != std::string::npos;
    //    }

    reg_t x86ToArm(const reg_t &r86) {
        auto it = registerMaps64.find(r86);
        if (it != registerMaps64.end()) {
            return it->second;
        }
        it = registerMaps32.find(r86);
        if (it != registerMaps32.end()) {
            return it->second;
        }
        zerror("Couldnt convert x86 register to aarch64!");
    }

    MemSize getMemOpSize(cs_x86_op m) {
        if (m.size == 4) {
            return MEM32;
        } else {
            return MEM64;
        }
    }

    reg_t getTmpRegByMemOpSize(TmpKind tmpkind, MemSize s) {
        return memPrefix[Aarch64][s] + tmp[tmpkind];
    }

    std::string armReg(x86_reg reg) {
        return assemblyUtils::x86ToArm(CapstoneUtils::getInstance().getRegName(reg));
    }

    std::string armImmidiate(int64_t value) { return "#" + std::to_string(value); }

    std::string armMemOp(const std::string &arg1, const std::string &arg2) {
        return "[" + arg1 + ", " + arg2 + "]";
    }

    std::string armMemOp(const std::string &arg) { return "[" + arg + "]"; }

    std::string armConvertOp(cs_x86_op op) {
        if (op.type == x86_op_type::X86_OP_REG) {
            return armReg(op.reg);
        } else if (op.type == x86_op_type::X86_OP_IMM) {
            return armImmidiate(op.imm);
        } else {
            zerror("Unexpected convert mem");
        }
    }
}// namespace assemblyUtils

// 1. mam skok do adresu x/
// 2. zostaw informację - w instrukcji skoku x daj adres instrukcji z-tej
// 3.

// Potrzebuję info
// 1. jaka jest instrukcja w adresie x-tym

// Instrukcja
// 1. wyczytaj czy jest operand grep \[rip + xd\]
// 2. wczytaj jakie bajty za niego odpowiadają

// convertowanie instrukcji

// 1. mam instrukcję
// 2. w jaki sposób wygenerować dla niej

// dane: string mający zapis instrukcji i jej rozmiar w bajtach
// ewentualna relokacja do drugiego argumentu
// oczekiwane:
// 1. zamienienie stringa na odpowiadający string z instrukcją
//      1.1 nauczyć się handlować wartości mem
//      1.2 jeżeli mem dotyczy
// 2. na jaki bajt przekoczy relokacja
// mov [rel],


#endif//CONVERTERPROJECT_ASSEMBLYUTILS_H
