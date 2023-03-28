//
// Created by mateusz on 26.03.23.
//

#ifndef CONVERTERPROJECT_ASSEMBLYUTILS_H
#define CONVERTERPROJECT_ASSEMBLYUTILS_H


#include "Utils.h"
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

#endif//CONVERTERPROJECT_ASSEMBLYUTILS_H
