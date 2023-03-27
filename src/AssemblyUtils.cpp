//
// Created by mateusz on 26.03.23.
//

#include "AssemblyUtils.h"
#include <map>
#include <string>


namespace utils {
    static std::string tmp[2] = {"12", "13"};
    static std::string memPrefix[2][2] = {{"w", "x"}, {"e", "r"}};

    static const std::map<std::string, std::string> registerMaps64 = {
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
    static std::map<std::string, std::string> registerMaps32 = {
            {"edi", "w0"},
            {"esi", "w1"},
            {"edx", "w2"},
            {"ecx", "w3"},
            {"r8d", "w4"},
            {"r9d", "w5"},
            {"eax", "w9"},
            {"r10d", "w10"},
            {"r11d", "w11"},
            {"ebp", "w29"},
            {"ebx", "w19"},
            {"r12d", "w20"},
            {"r13d", "w21"},
            {"r14d", "w22"},
            {"r15d", "w23"},
    };
}
reg_t AssemblyUtils::convertRegisterMemSize(AssemblyUtils::Arch arch, AssemblyUtils::MemSize memSize, const reg_t &r) {
    std::string suffix = r.substr(1);
    reg_t r64 = utils::memPrefix[arch][memSize] + suffix;
    return r64;
}
reg_t AssemblyUtils::x86ToArm(const reg_t &r86) {
    auto it = utils::registerMaps64.find(r86);
    if (it != utils::registerMaps64.end()) {
        return it->second;
    }
    it = utils::registerMaps32.find(r86);
    if (it != utils::registerMaps32.end()) {
        return it->second;
    }
    zerror("Couldnt convert x86 register to aarch64!");
}
reg_t AssemblyUtils::getTmpRegByMemOpSize(AssemblyUtils::TmpKind tmpkind, AssemblyUtils::MemSize s) {
    return utils::memPrefix[Aarch64][s] + utils::tmp[tmpkind];
}
