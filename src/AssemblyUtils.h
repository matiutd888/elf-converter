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


class AssemblyUtils {
public:
    static const int ARM_INSTRUCTION_SIZE_BYTES = 4;
    enum Arch { Aarch64 = 0,
                X86_64 = 1 };

    enum MemSize { MEM32 = 0,
                   MEM64 = 1 };

    enum TmpKind {
        TMP1 = 0,
        TMP2 = 1,
    };

    // Works for Arm and x86
    static reg_t convertRegisterMemSize(Arch arch, MemSize memSize, const reg_t &r);
    //    bool isRegister(std::string s) {
    //        return registerMaps32.find(s) != registerMaps32.end() ||
    //        registerMaps64.find(s) != registerMaps64.end();
    //    }
    //
    //    bool isMem(std::string operand) {
    //        return operand.find("[")  != std::string::npos;
    //    }

    static reg_t x86ToArm(const reg_t &r86);

    static MemSize getMemOpSize(cs_x86_op m) {
        if (m.size == 4) {
            return MEM32;
        } else {
            return MEM64;
        }
    }

    static reg_t getTmpRegByMemOpSize(TmpKind tmpkind, MemSize s);

    static inline std::string armReg(x86_reg reg) {
        return AssemblyUtils::x86ToArm(CapstoneUtils::getInstance().getRegName(reg));
    }


    static inline std::string armUImmidiate(uint64_t value) { return "#" + std::to_string(value); }

    static inline std::string armImmidiate(int64_t value) { return "#" + std::to_string(value); }

    static inline std::string armMemOp(const std::string &arg1, const std::string &arg2) {
        return "[" + arg1 + ", " + arg2 + "]";
    }

    static inline std::string armMemOp(const std::string &arg) { return "[" + arg + "]"; }

    static inline std::string armConvertOp(cs_x86_op op) {
        if (op.type == x86_op_type::X86_OP_REG) {
            return armReg(op.reg);
        } else if (op.type == x86_op_type::X86_OP_IMM) {
            return armImmidiate(op.imm);
        } else {
            zerror("Unexpected convert mem");
        }
    }
};

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
