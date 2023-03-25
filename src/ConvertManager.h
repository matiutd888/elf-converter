//
// Created by mateusz on 12.03.23.
//

#ifndef CONVERTERPROJECT_CONVERTMANAGER_H
#define CONVERTERPROJECT_CONVERTMANAGER_H

#include "utils.h"
#include <cassert>
#include <elfio/elfio.hpp>
#include <map>
#include <optional>
#include <ostream>
#include <algorithm>
#include <variant>
#include <queue>

using namespace ELFIO;

#define mDebug (std::cout << "DEBUG: ")
#define mWarn (std::cout << "WARN: ")
#define todo(S) (zerror("TODO" S))
#define strEqual(I, J) (strcmp((I), (J)) == 0)

using address_t = Elf64_Addr;

// TODO więcej adresów do relokacji / braku relokajci?

class FileChecker {
public:
    static bool checkFile(const elfio &file);
};

struct Symbol {
private:
    static constexpr Elf_Word specialUnhandledSections[1] = {SHN_COMMON};

public:
    std::string name;
    // Address in section
    //    In relocatable files, st_value holds alignment constraints for a symbol
    //    whose section index is SHN_COMMON. In relocatable files, st_value holds
    //    a section offset for a defined symbol. That is, st_value is an offset
    //    from the beginning of the section that st_shndx identifies.
    Elf64_Addr value;
    Elf_Xword size;
    unsigned char bind;
    unsigned char type;
    unsigned char other;

    static bool isExternal(Elf_Half sectionIndex) {
        return sectionIndex == SHN_UNDEF;
    }

    bool isGlobal(Elf_Half sectionIndex) const {
        return (type == STT_FILE) | isExternal(sectionIndex);
    }

    static bool isSpecial(Elf_Half sectionIndex) {
        std::ranges::any_of(
                specialUnhandledSections,
                [sectionIndex](Elf_Word x) -> bool { return x == sectionIndex; });
    }

    bool isFunction() const { return type == STT_FUNC; }

    friend std::ostream &operator<<(std::ostream &os, const Symbol &symbol) {
        os << "name: " << symbol.name << " value: " << symbol.value
           << " size: " << symbol.size << " bind: " << symbol.bind
           << " type: " << symbol.type << " other: " << symbol.other;
        return os;
    }
};

class Relocation {
public:
    Elf64_Addr offset;
    Elf_Word symbol;
    unsigned type;
    Elf_Sxword addend;

    Relocation() = default;

    Relocation(Elf64_Addr offset, Elf_Word symbol, unsigned type, Elf_Sxword addend) : offset(offset), symbol(symbol),
                                                                                       type(type), addend(addend) {}

    static bool isRelocationHandled(unsigned type) {
        return type == R_X86_64_PC32 | type == R_X86_64_PLT32 |
               type == R_X86_64_32 | type == R_X86_64_32S | type == R_X86_64_64;
    }

    friend std::ostream &operator<<(std::ostream &os,
                                    const Relocation &relocation) {
        os << "offset: " << relocation.offset << " symbol: " << relocation.symbol
           << " type: " << relocation.type << " addend: " << relocation.addend;
        return os;
    }
};

class MAddress {
    std::optional<address_t> relativeToSection;
    std::optional<address_t> relativeToInstruction;
    std::optional<address_t> relativeToFunction;

public:
    void setRelativeToFunction(address_t relativeToFunction) {
        this->relativeToFunction = relativeToFunction;
    }

    void setRelativeToSection(address_t relativeToSection) {
        this->relativeToSection = relativeToSection;
    }

    void setRelativeToInstruction(address_t relativeToInstruction) {
        this->relativeToInstruction = relativeToInstruction;
    }

    address_t getRelativeToFunction() const {
        return relativeToFunction.value();
    }
};

class RelocationWithMAddress {
    Relocation r;
public:
    MAddress maddress;

    unsigned type() const {
        return r.type;
    };

    Elf_Word symbol() const {
        return r.symbol;
    }

    Elf_Sxword addend() const {
        return r.addend;
    }

    explicit RelocationWithMAddress(const Relocation &r) : r(r) {}
};

using reg_t = std::string;

namespace assemblyUtils {
    const int ARM_INSTRUCTION_SIZE_BYTES = 32;

    namespace {

        std::string tmp[2] = {"12", "13"};
        std::string memPrefix[2][2] = {{"w", "x"},
                                       {"e", "r"}};

        const std::map<std::string, std::string> registerMaps64 = {
                {"rdi", "x0"},
                {"rsi", "x1"},
                {"rdx", "x2"},
                {"rcx", "x3"},
                {"r8",  "x4"},
                {"r9",  "x5"},
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
                {"e8",  "w4"},
                {"e9",  "w5"},
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
    }

    enum Arch {
        Aarch64 = 0,
        X86_64 = 1
    };

    enum MemSize {
        MEM32 = 0, MEM64 = 1
    };

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

    MemSize getMemOpSize(x86_op_mem m) {
        todo("Learn how to deduce mem op size");
        return MemSize::MEM64;
    }

    reg_t getTmpRegByMemOpSize(TmpKind tmpkind, MemSize s) {
        return memPrefix[Aarch64][s] + tmp[tmpkind];
    }

    std::string x86RegToString(x86_reg reg) {
        todo("implement");
        return "";
    }

    std::string armReg(x86_reg reg) {
        return assemblyUtils::x86ToArm(x86RegToString(reg));
    }

    std::string armImmidiate(int64_t value) {
        return "#" + std::to_string(value);
    }

    std::string armMemOp(const std::string &arg1, const std::string &arg2) {
        return "[" + arg1 + ", " + arg2 + "]";
    }

    std::string armMemOp(const std::string &arg) {
        return "[" + arg + "]";
    }


    std::string armConvertOp(cs_x86_op op) {
        if (op.type == x86_op_type::X86_OP_REG) {
            return armReg(op.reg);
        } else if (op.type == x86_op_type::X86_OP_IMM) {
            return armImmidiate(op.imm);
        } else {
            todo("Unable to convert mem");
        }
    }
} // namespace assemblyUtils

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

struct ArmInstructionStub {
    static void sizeAssert(const std::string &content, size_t size) {
        if (content.empty()) {
            assert(size == 0);
        } else {
            assert(size % assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES == 0);
            assert(std::count(content.begin(), content.end(), '\n') + 1 ==
                   size / assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES);
        }
    }

public:
    std::string content;
    size_t size;
    // !IMPORTANT Will have offsets relative to instruction (STUB!) address, not
    // function address!
    // TODO this should probably be renamed to just relocations, as I will not analyze for changes relative to original relocation that much.
    // But this is just an idea.
//    std::vector<RelocationWithMAddress> relocations;

    ArmInstructionStub(const std::string &content, size_t size) : content(content),
                                                                  size(size) {


        sizeAssert(content, size);
    }
};


using armStubWithRels_t = std::pair<ArmInstructionStub, std::vector<RelocationWithMAddress>>;

armStubWithRels_t createArmStubWithRels(const ArmInstructionStub &a, const std::vector<Relocation> &rel) {
    std::vector<RelocationWithMAddress> r;
    std::transform(rel.begin(), rel.end(),
                   std::back_inserter(r),
                   [](Relocation r) -> RelocationWithMAddress {
                       auto ret = RelocationWithMAddress(r);
                       ret.maddress.setRelativeToInstruction(r.offset);
                       return ret;
                   });

    return {a, r};
}

armStubWithRels_t createArmStubWithRels(const ArmInstructionStub &a) {
    return {a, std::vector<RelocationWithMAddress>()};
}

class JumpInstructionToFill {
    static const size_t SIZE = assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES;
    reg_t mnemonic;
    address_t addressToConvert;
public:
    JumpInstructionToFill(const reg_t &mnemonic, address_t addressToConvert) : mnemonic(mnemonic),
                                                                               addressToConvert(addressToConvert) {

    }

    size_t size() {
        return SIZE;
    }
};

class HandleInstrResult {
    std::variant<armStubWithRels_t, JumpInstructionToFill> content;
public:
    static const size_t ARM_INSTRUCTION_STUB_TYPE = 0;
    static const size_t JUMP_INSTRUCTION_TO_FILL_TYPE = 1;

    explicit HandleInstrResult(const std::variant<armStubWithRels_t, JumpInstructionToFill> &a) : content(a) {}

    size_t getType() const {
        return content.index();
    }

    size_t size() {
        if (getType() == ARM_INSTRUCTION_STUB_TYPE) {
            const ArmInstructionStub &a = std::get<armStubWithRels_t>(content).first;
            return a.size;
        } else if (getType() == JUMP_INSTRUCTION_TO_FILL_TYPE) {
            return std::get<JumpInstructionToFill>(content).size();
        } else {
            zerror("Wrong type of HandleInstrResult");
        }
    }
};


class InstructionBuilder {
    // Lord forvie me for O(n^2) complexity of this code
    std::string ret;

    static std::string makeInstr(const std::string &instruction,
                                 const std::string &arg1,
                                 const std::string &arg2) {
        return instruction + " " + arg1 + ", " + arg2;
    }

    static std::string makeInstr(const std::string &instruction,
                                 const std::string &arg1) {
        return instruction + " " + arg1;
    }

public:
    explicit InstructionBuilder(const std::string &s) : ret(s) {}

    InstructionBuilder(const std::string &instruction, const std::string &arg1)
            : ret(makeInstr(instruction, arg1)) {}

    InstructionBuilder(const std::string &instruction, const std::string &arg1,
                       const std::string &arg2)
            : ret(makeInstr(instruction, arg1, arg2)) {}

    InstructionBuilder append(const std::string &instruction,
                              const std::string &arg1) {
        InstructionBuilder(ret + "\n" + makeInstr(instruction, arg1));
    }

    InstructionBuilder append(const std::string &instruction,
                              const std::string &arg1, const std::string &arg2) {
        InstructionBuilder(ret + "\n" + makeInstr(instruction, arg1, arg2));
    }

    std::string build() { return ret; }
};

namespace InstructionConverter {
    void commonMemAsserts(x86_op_mem mem) { assert(mem.index == 0); }

    armStubWithRels_t convertNonRelocableMemOperand(assemblyUtils::TmpKind tmp1Kind, x86_op_mem op,
                                                    const reg_t &reg) {
        reg_t tmp164 = assemblyUtils::getTmpRegByMemOpSize(tmp1Kind, assemblyUtils::MEM64);
        return createArmStubWithRels(ArmInstructionStub(
                InstructionBuilder("mov", tmp164, assemblyUtils::armImmidiate(op.disp))
                        .append("ldr", reg, assemblyUtils::armMemOp(assemblyUtils::armReg(op.base), tmp164))
                        .build(),
                assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 2
        ));
    }


    // Przyklad
// cmp qword ptr [rip + _], 2137
// ^ chcemy zamienić cmp [rip + _] na
// ldr tmp1, #0
// gdzie na #0 jest relatywna relokacja.
// w takim wypadku
// operandPositionInInstruction = 3, bo na 3ci bajt (licząc od zera) od adresu
// instrukcji cmp będzie ustawiony adres relokacji
// pierwszy operand cmp odnosi się do
// rip + (adresSymbolu - (adresInstrukcji + operandPositionInInstruction) + addend)
// = adresSymbolu - operandPositionInInstruction + addend + (rip - adresInstrukcji)
// = adresSymbolu - operandPositionInInstruction + addend + ROZMIAR_INSTRUKCJI_x86
// i do tego samego adresu sami musimy się odnieść w armie.
// instrukcja ldr z liczbą x odnosi się do adresu pc + x
// a relokacja R_AARCH64_LD_PREL_LO19 ma wartość relokowaną (adresSymbolu + addend - offsetRelokacji)
// W armie offsetRelokacji jest równy adresowi instrukcji, czyli PC.
// więc
// relokacja ostatecaznie będzie się odnosić do (adresSymbolu + addend - PC) + PC (dodaje PC bo
// taka jest semantyka ldr) = adresSymbolu + addend
// W takim wypadku relokacja w armie (która ma adres równy adresowi instrukcji)
// powinna mieć taki addendArm, że  będzie równy temu do czego odnosił się pierowtny operand, czyli
// adresSymbolu  + addendArm = adresSymbolu - operandPositionInInstruction + addendx86 + ROZMIAR_INSTRUKCJI_x86
// Z tego mamy:
// addendArm = addendx86 - operandPositionInInstruction + ROZMIAR_INSTRUKCJI_x86
// https://reverseengineering.stackexchange.com/questions/17666/how-does-the-ldr-instruction-work-on-arm
// Wczytaj op do reg
    armStubWithRels_t
    convertRelocableMemOperand(const reg_t &reg, const RelocationWithMAddress &rel,
                               size_t operandPositionInInstruction,
                               size_t x86InsSize) {
        Relocation retRel(0, rel.symbol(), R_AARCH64_LD_PREL_LO19, rel.addend() + (Elf_Sword) x86InsSize -
                                                                   (Elf_Sword) operandPositionInInstruction);
        return createArmStubWithRels(ArmInstructionStub(
                InstructionBuilder("ldr", reg, assemblyUtils::armImmidiate(0)).build(),
                assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES), {retRel});
    }

    // relocationPositionInInstruction
// if operand is [rip + x], what byte is x in in the instruction
// example: cmp qword ptr [rip + _], 2137 would have relocation for the byte 3
// cmp qword ptr [rip + _], 2137 would be having relocation for byte 2
// TODO maybe tmpToUse should ALWAYS be tmp1
// It doesnt hurt us even when reg is tmp1 probably
    armStubWithRels_t readMemOpToReg(const std::vector<RelocationWithMAddress> &relocations,
                                     const reg_t &reg,
                                     x86_op_mem op,
                                     cs_insn *ins,
                                     assemblyUtils::TmpKind tmpToUse // tmpToUse is index of free tmp register
            // this probably can be read from relocations[0].offset - ins->address
    ) {
        commonMemAsserts(op);
        switch (op.base) {
            case X86_REG_RIP: {
                assert(relocations[0].type() == R_X86_64_PC32 ||
                       relocations[0].type() == R_X86_64_PLT32);
                size_t relocationPositionInInstruction =
                        relocations[0].maddress.getRelativeToFunction() - ins->address;
                return convertRelocableMemOperand(
                        reg, relocations[0], relocationPositionInInstruction, ins->size);
            }
            default:
                return convertNonRelocableMemOperand(tmpToUse, op, reg);
        }
    }

    namespace cmpHandler {
        namespace {
            armStubWithRels_t
            handleCmpReg(cs_insn *ins,
                         const std::vector<RelocationWithMAddress> &relatedRelocations
            ) {
                switch (ins->detail->x86.operands[1].type) {
                    case X86_OP_REG:
                    case X86_OP_IMM:
                        return
                                createArmStubWithRels(ArmInstructionStub(
                                                              InstructionBuilder("cmp",
                                                                                 assemblyUtils::armConvertOp(ins->detail->x86.operands[0]),
                                                                                 assemblyUtils::armConvertOp(ins->detail->x86.operands[1]))
                                                                      .build(),
                                                              assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES
                                                      )
                                );
                    case X86_OP_MEM: {
                        auto m = ins->detail->x86.operands[1].mem;
                        auto memOpSize = assemblyUtils::getMemOpSize(m);
                        reg_t tmp = assemblyUtils::getTmpRegByMemOpSize(assemblyUtils::TMP1, memOpSize);
                        auto c = readMemOpToReg(relatedRelocations,
                                                tmp,
                                                m,
                                                ins,
                                                assemblyUtils::TMP2);
                        c.first.size +=
                                assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES;
                        c.first.
                                content = InstructionBuilder(c.first.content)
                                .append("cmp", assemblyUtils::armConvertOp(ins->detail->x86.operands[0]), tmp)
                                .build();
                        return
                                c;
                    }
                    default:
                        zerror("handleCmpReg: Invalid second operand");
                }
            }


            armStubWithRels_t
            handleCmpMem(cs_insn *ins,
                         const std::vector<RelocationWithMAddress> &relatedRelocations
            ) {
                x86_op_mem m = ins->detail->x86.operands[0].mem;
                auto memOpSize = assemblyUtils::getMemOpSize(m);
                reg_t tmp = assemblyUtils::getTmpRegByMemOpSize(assemblyUtils::TMP1, memOpSize);
                auto c = readMemOpToReg(relatedRelocations,
                                        tmp,
                                        m,
                                        ins,
                                        assemblyUtils::TMP2);
                c.first.size +=
                        assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES;
                c.first.
                        content = InstructionBuilder(c.first.content)
                        .append("cmp", tmp, assemblyUtils::armConvertOp(ins->detail->x86.operands[1]))
                        .build();
                return
                        c;
            }

        }

        armStubWithRels_t
        handleCmp(cs_insn *ins,
                  const std::vector<RelocationWithMAddress> &relatedRelocations
        ) {
            assert(ins->detail->x86.op_count == 2);
            assert(relatedRelocations.empty());
            switch (ins->detail->x86.operands[0].type) {
                case X86_OP_REG:
                    return
                            handleCmpReg(ins, relatedRelocations
                            );
                case X86_OP_MEM:
                    // Popatrz, do jakiej wielkości mem
                    // wczytaj op
                    // cmp mem, reg/imm
                    // cmp {tmp1}, {op2}

                    // co jest możliwe
                    // cmp mem64, imm32
                    // trzeba to przetłumaczyć na
                    // cmp tmp1.32, imm32;
                    // cmp
                    return
                            handleCmpMem(ins, relatedRelocations
                            );
                default:
                    zerror("cmp: Invalid operand type");
            }
        }
    }


    namespace movHandler {
        namespace {
            armStubWithRels_t
            handleMovReg(cs_insn *ins, const std::vector<RelocationWithMAddress> &relatedRelocations) {
                switch (ins->detail->x86.operands[1].type) {
                    case x86_op_type::X86_OP_MEM:
                        return readMemOpToReg(relatedRelocations,
                                              assemblyUtils::armReg(ins->detail->x86.operands[0].reg),
                                              ins->detail->x86.operands[1].mem,
                                              ins,
                                              assemblyUtils::TMP1
                        );
                    case x86_op_type::X86_OP_IMM:
                        if (!relatedRelocations.empty() &&
                            (relatedRelocations[0].type() == R_X86_64_32 ||
                             relatedRelocations[0].type() == R_X86_64_32S)) {

                            // Addendu nie zmieniamy, bo relokacja nie jest relatywna
                            Relocation r(
                                    0,
                                    relatedRelocations[0].symbol(),
                                    R_AARCH64_ADR_PREL_LO21,
                                    relatedRelocations[0].addend()
                            );
                            auto instr = InstructionBuilder("adr",
                                                            assemblyUtils::convertRegisterMemSize(assemblyUtils::X86_64,
                                                                                                  assemblyUtils::MEM64,
                                                                                                  assemblyUtils::x86RegToString(
                                                                                                          ins->detail->x86.operands[0].reg)),
                                                            assemblyUtils::armImmidiate(0)).build();
                            return createArmStubWithRels(ArmInstructionStub(
                                                                 instr,
                                                                 assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES),
                                                         {r});
                        } else {
//                            TODO tego elsa można nie zrobić i wtedy po prostu wpadniemy w case reg
                            break;
                        }
                    case x86_op_type::X86_OP_REG:
                        break;
                    default:
                        zerror("Error handling mov");
                }
                return createArmStubWithRels({
                                                     InstructionBuilder("mov",
                                                                        assemblyUtils::armConvertOp(
                                                                                ins->detail->x86.operands[0]),
                                                                        assemblyUtils::armConvertOp(
                                                                                ins->detail->x86.operands[1])).build(),
                                                     assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES});
            }

            armStubWithRels_t
            handleMovMemNonRipBase(cs_insn *ins, const std::vector<RelocationWithMAddress> &relatedRelocations) {
                auto mem = ins->detail->x86.operands[0].mem;
                switch (ins->detail->x86.operands[1].type) {
                    case X86_OP_IMM: {
                        if (!relatedRelocations.empty() &&
                            (relatedRelocations[0].type() == R_X86_64_32 ||
                             relatedRelocations[0].type() == R_X86_64_32S)) {

                            // Addendu nie zmieniamy, bo w nierelatywnych (R_X86_64_32, R_X86_64_32S) relokacjach położenie określane było przez po prostu adres symbolu + addend
                            Relocation r = Relocation(
                                    0,
                                    relatedRelocations[0].symbol(),
                                    R_AARCH64_ADR_PREL_LO21,
                                    relatedRelocations[0].addend()
                            );
                            auto tmp164 = assemblyUtils::getTmpRegByMemOpSize(assemblyUtils::TMP1,
                                                                              assemblyUtils::MEM64);
                            auto tmp264 = assemblyUtils::getTmpRegByMemOpSize(assemblyUtils::TMP2,
                                                                              assemblyUtils::MEM64);
                            auto instr = InstructionBuilder("adr",
                                                            tmp164,
                                                            assemblyUtils::armImmidiate(0))
                                    .append("mov", tmp264,
                                            assemblyUtils::armImmidiate(mem.disp))
                                    .append("str",
                                            assemblyUtils::getTmpRegByMemOpSize(
                                                    assemblyUtils::TMP1,
                                                    assemblyUtils::getMemOpSize(mem)),
                                            assemblyUtils::armMemOp(assemblyUtils::armReg(mem.base), tmp264))
                                    .build();
                            return createArmStubWithRels(ArmInstructionStub(
                                                                 instr,
                                                                 assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 3),
                                                         {r});
                        }
                    }
                    case X86_OP_REG:
                        break;
                    default:
                        zerror("handleMovMemNonRipBase: Invalid operand type");
                }
                auto tmp1 = assemblyUtils::getTmpRegByMemOpSize(assemblyUtils::TMP1, assemblyUtils::getMemOpSize(mem));
                auto tmp264 = assemblyUtils::getTmpRegByMemOpSize(assemblyUtils::TMP2, assemblyUtils::MEM64);
                auto instr = InstructionBuilder("mov", tmp1, assemblyUtils::armConvertOp(ins->detail->x86.operands[1]))
                        .append("mov", tmp264, assemblyUtils::armImmidiate(mem.disp))
                        .append("str", tmp1, assemblyUtils::armMemOp(assemblyUtils::armReg(mem.base), tmp264))
                        .build();
                return createArmStubWithRels({instr,
                                              assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 3});
            }

            armStubWithRels_t
            handleMovMemRipBase(cs_insn *ins, const std::vector<RelocationWithMAddress> &relatedRelocations) {
                auto m = ins->detail->x86.operands[0].mem;
                assert(relatedRelocations.size() == 1);
                assert(relatedRelocations[0].type() == R_X86_64_PC32 ||
                       relatedRelocations[0].type() == R_X86_64_PLT32);
                size_t relocationOffsetInInstruction =
                        relatedRelocations[0].maddress.getRelativeToFunction() - ins->address;
                Elf_Sxword newAddend = relatedRelocations[0].addend() + (Elf_Sxword) ins->size -
                                       (Elf_Sxword) relocationOffsetInInstruction;
                Relocation r = Relocation(
                        0,
                        relatedRelocations[0].symbol(),
                        R_AARCH64_ADR_PREL_LO21,
                        newAddend);
                reg_t tmp2 = assemblyUtils::getTmpRegByMemOpSize(assemblyUtils::TMP2,
                                                                 assemblyUtils::getMemOpSize(m));
                reg_t tmp164 = assemblyUtils::getTmpRegByMemOpSize(assemblyUtils::TMP1, assemblyUtils::MEM64);
                auto instr = InstructionBuilder("adr", tmp164, assemblyUtils::armImmidiate(0))
                        .append("mov", tmp2, assemblyUtils::armConvertOp(ins->detail->x86.operands[1]))
                        .append("str", tmp2, assemblyUtils::armMemOp(tmp164)).build();
                return createArmStubWithRels(ArmInstructionStub(
                                                     instr,
                                                     3 * assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES),
                                             {r}
                );
            }

            armStubWithRels_t
            handleMovMem(cs_insn *ins, const std::vector<RelocationWithMAddress> &relatedRelocations) {
                auto m = ins->detail->x86.operands[0].mem;
                commonMemAsserts(ins->detail->x86.operands[0].mem);
                switch (m.base) {
                    case X86_REG_RIP:
                        return handleMovMemRipBase(ins, relatedRelocations);
                    default:
                        return handleMovMemNonRipBase(ins, relatedRelocations);
                }
            }

        }

        armStubWithRels_t handleMov(cs_insn *ins, const std::vector<RelocationWithMAddress> &relatedRelocations) {
            assert(ins->detail->x86.op_count = 2);
            switch (ins->detail->x86.operands[0].type) {
                case x86_op_type::X86_OP_REG:
                    return handleMovReg(ins, relatedRelocations);
                case x86_op_type::X86_OP_MEM:
                    return handleMovMem(ins, relatedRelocations);
                default:
                    zerror(&"mov: Incorrect first operand type: "[ins->detail->x86.operands[0].type]);
            }
        }
    }


    namespace callHandler {
        armStubWithRels_t
        handleCall(cs_insn *ins, const std::vector<RelocationWithMAddress> &relatedRelocations) {
            assert(ins->detail->x86.op_count == 1);
            assert(relatedRelocations.size() == 1);

            // fAddr: f
            // rel f
            // addr: call _
            // call f
            // rip: e8 XX XX XX XX
            // gdzie XX..XX musi mieć wartość równą (adres f - adres końca instrukcji) =
            // fAddr - (adresInstrukcji + 5) // Z tego wynika, że wartość relokowalna
            // musi być taka, że fAddr - (adresInstrukcji + 1) + addend = fAddr -
            // adresInstrukcji - 5 => addend = -4 semantyka bl bl x idzie do PC + x
            // czyli muszę dodać taką relokację, że
            // 1. do jakiego adresu idzie call f
            // (symaddr - (adresInstrukcji + 1) + addend) = newAddr - (adresInstrukcji +
            // 5) newAddr = symAddr + a + 4
            // 2. do jakiego adresu idzie bl _
            // https://stackoverflow.com/questions/15671717/relocation-in-assembly
            // symAddr - PC + a2 = newAddr - PC
            // newAddr = symAddr + a2
            // symAddr + a + 4 = symAdr + a2
            // a2 = a + 4
            Relocation r = Relocation(
                    0,
                    relatedRelocations[0].symbol(),
                    R_AARCH64_CALL26,
                    relatedRelocations[0].addend() + 4
            );
            return createArmStubWithRels(ArmInstructionStub(
                    InstructionBuilder("bl", assemblyUtils::armImmidiate(0))
                            .append("mov", "x9", "x0")
                            .build(),
                    assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 2), {r});
        }
    } // namespace callHandler

    namespace arithmeticInstructionHandler {
        armStubWithRels_t
        handleAdd(cs_insn *ins,
                  const std::vector<RelocationWithMAddress> &relatedRelocations
        ) {
            assert(ins->detail->x86.op_count == 2);
            assert(ins->detail->x86.operands[0].type == x86_op_type::X86_OP_REG);
            assert(relatedRelocations.empty());

            return

                    createArmStubWithRels(ArmInstructionStub(
                                                  InstructionBuilder("add",
                                                                     assemblyUtils::armConvertOp(ins->detail->x86.operands[0]),
                                                                     assemblyUtils::armConvertOp(ins->detail->x86.operands[1])).build(),
                                                  assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES

                                          )
                    );
        }

        armStubWithRels_t
        handleSub(cs_insn *ins, const std::vector<RelocationWithMAddress> &relatedRelocations) {
            assert(ins->detail->x86.op_count == 2);
            assert(ins->detail->x86.operands[0].type == x86_op_type::X86_OP_REG);
            assert(relatedRelocations.empty());

            return createArmStubWithRels(ArmInstructionStub(
                    InstructionBuilder("sub",
                                       assemblyUtils::armConvertOp(ins->detail->x86.operands[0]),
                                       assemblyUtils::armConvertOp(ins->detail->x86.operands[1])).build(),
                    assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES
            ));
        }

    } // namespace arithmeticInstructionHandler

    namespace jmpHandler {
        namespace {
            std::map<std::string, std::string> conditionalMap = {
                    {"a",   "hi"},
                    {"ae",  "hs"},
                    {"b",   "lo"},
                    {"be",  "ls"},
                    {"e",   "eq"},
                    {"g",   "gt"},
                    {"ge",  "ge"},
                    {"l",   "lt"},
                    {"le",  "le"},
                    {"na",  "ls"},
                    {"nae", "lo"},
                    {"nb",  "hs"},
                    {"nbe", "hi"},
                    {"ne",  "ne"},
                    {"ng",  "le"},
                    {"nge", "lt"},
                    {"nl",  "ge"},
                    {"nle", "gt"},
                    {"no",  "vc"},
                    {"nz",  "ne"},
                    {"o",   "vs"},
                    {"z",   "eq"},
            };
        }

        bool isConditionalJump(const std::string &mnemonic) {
            if (mnemonic.length() == 0) {
                return false;
            }
            if (mnemonic[0] != 'j') {
                return false;
            }
            return conditionalMap.find(mnemonic.substr(1)) != conditionalMap.end();
        }

        JumpInstructionToFill handleJmp(cs_insn *ins, const std::vector<RelocationWithMAddress> &relatedRelocations) {
            assert(ins->detail->x86.op_count == 1);
            assert(relatedRelocations.empty());
            assert(ins->detail->x86.operands[0].type == X86_OP_IMM);

            return JumpInstructionToFill("b", ins->detail->x86.operands[0].imm);
        }

        JumpInstructionToFill
        handleConditionalJmp(cs_insn *ins, const std::vector<RelocationWithMAddress> &relatedRelocations) {
            assert(ins->detail->x86.op_count == 1);
            assert(relatedRelocations.empty());
            assert(ins->detail->x86.operands[0].type == X86_OP_IMM);


            std::string mnemonic = std::string(ins->mnemonic);
            std::string armSuffix = conditionalMap[mnemonic.substr(1)];
            return JumpInstructionToFill("b" + armSuffix, ins->detail->x86.operands[0].imm);
        }
    }


    HandleInstrResult handleInstruction(cs_insn *ins, const std::vector<RelocationWithMAddress> &relatedRelocations) {
        if (strEqual(ins->mnemonic, "add")) {
            return HandleInstrResult(arithmeticInstructionHandler::handleAdd(ins, relatedRelocations));
        } else if (strEqual(ins->mnemonic, "sub")) {
            return HandleInstrResult(arithmeticInstructionHandler::handleSub(ins, relatedRelocations));
        } else if (strEqual(ins->mnemonic, "cmp")) {
            return HandleInstrResult(cmpHandler::handleCmp(ins, relatedRelocations));
        } else if (strEqual(ins->mnemonic, "call")) {
            return HandleInstrResult(callHandler::handleCall(ins, relatedRelocations));
        } else if (strEqual(ins->mnemonic, "mov")) {
            return HandleInstrResult(movHandler::handleMov(ins, relatedRelocations));
        } else if (strEqual(ins->mnemonic, "jmp")) {
            return HandleInstrResult(jmpHandler::handleJmp(ins, relatedRelocations));
        } else if (jmpHandler::isConditionalJump(ins->mnemonic)) {
            return HandleInstrResult(jmpHandler::handleConditionalJmp(ins, relatedRelocations));
        }
    }; // namespace InstructionConverter
}


struct JumpInstruction {
    size_t fromIndex;
    size_t toIndex;
};

class FunctionData {
    const int X64_PROLOGUE_SIZE = 3;
    const int X64_EPILOGUE_SIZE = 2;
    const int ARM_PROLOG_SIZE_BYTES =
            assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 2;
    address_t baseAddress;

    CapstoneUtils utils;
    cs_insn *insn;
    size_t numberOfInstructions;

    bool converted;

    std::vector<ArmInstructionStub> armInstructions;
    std::vector<address_t> armInstructionAddresses;

    std::vector<JumpInstruction> jumps;

    // This will be needed for jumps
    size_t findInstructionByRelativeAddress(address_t x) { todo("Implement"); }

    // TODO nie obsługuję skoczenia do ŚRODKA prologu (umiem skoczyć jedynie na
    // początek)
    void convertPrologue() {
        assert(strEqual(insn[0].mnemonic, "endbr64"));
        assert(strEqual(insn[1].mnemonic, "push") &&
               strEqual(insn[1].op_str, "rbp"));
        assert(strEqual(insn[2].mnemonic, "mov") &&
               strEqual(insn[2].op_str, "rbp, rsp"));

        armInstructions.push_back(
                ArmInstructionStub


        InstructionBuilder("stp x29, x30, [sp, #-16]!")
                .append("mov", "x29", "sp")
                .build());

        armInstructions.emplace_back("");
        armInstructions.emplace_back("");

        armInstructionAddresses.push_back(0);
        armInstructionAddresses.push_back(ARM_PROLOG_SIZE_BYTES);
        armInstructionAddresses.push_back(ARM_PROLOG_SIZE_BYTES);
    }

    // TODO nie obsługuję skoczenia do ŚRODKA epilogu (umiem skoczyć jedynie na
    // początek)
    void convertEpilogue() {
        assert(strEqual(insn[numberOfInstructions - 2].mnemonic, "leave"));
        assert(strEqual(insn[numberOfInstructions - 1].mnemonic, "ret"));

        armInstructions.emplace_back("mov x0, x9\n"
                                     "add sp, x29, #16\n"
                                     "ldp x29, x30, [sp, #-16]\n"
                                     "ret");
        armInstructions.emplace_back("");
    }

    static bool
    checkIfAddressBetweenInstruction(address_t offsetFromBase,
                                     address_t instructionOffsetFromBase,
                                     size_t instructionSize) {
        return offsetFromBase >= instructionOffsetFromBase &&
               offsetFromBase <= instructionOffsetFromBase + instructionSize;
    }

    address_t getLastInstructionAddress() {
        assert(armInstructionAddresses.size() > 0);
    }

public:
    FunctionData(const char *rawData, size_t size, address_t baseAddress) {
        //        raw.insert(raw.begin(), rawData, rawData + size);
        numberOfInstructions = utils.disassemble(
                reinterpret_cast<const uint8_t *>(rawData), size, insn);
        converted = false;
        baseAddress = baseAddress;
    }

    std::vector<Relocation> convert(std::vector<Relocation> relatedRelocations) {
        assert(std::is_sorted(relatedRelocations.begin(), relatedRelocations.end(), [](auto r1, auto r2) -> bool {
            return r1.offset < r2.offset;
        }));
        std::queue<RelocationWithMAddress> q;

        for (const auto &r: relatedRelocations) {
            RelocationWithMAddress rM(r);
            rM.maddress.setRelativeToSection(r.offset);
            rM.maddress.setRelativeToFunction(r.offset - baseAddress);
            q.push(rM);
        }

        convertPrologue();
        for (int i = X64_PROLOGUE_SIZE; i < numberOfInstructions - X64_EPILOGUE_SIZE; i++) {
            todo("Check if relocation is in this instruction");
            std::vector<RelocationWithMAddress> r;
            while (!q.empty() &&
                   checkIfAddressBetweenInstruction(q.front().maddress.getRelativeToFunction(), insn[i].address,
                                                    insn[i].size)) {
                r.push_back(q.front());
                q.pop();
            }
            auto c = InstructionConverter::handleInstruction(&insn[i], r);


            todo("Adjust relocations returned by converter - they are relative to "
                 "instruction address, should be changed relative to section base "
                 "address");

        }
        convertEpilogue();
    }

    // This probably will not be neccessaru
    address_t getNewAddress(address_t oldAddress) {
        if (!converted) {
            zerror("Function hasn't been converted yet");
        }
    }
};

struct SectionData {
    section *s;
    std::vector<Symbol> symbols;
    std::vector<Relocation> relocations;
};

class SectionManager {
    SectionData originalSectionData;
    SectionData newSectionData;
    std::vector<FunctionData> functions;
    std::vector<std::vector<Relocation>> functionsRelocations;

public:
    explicit SectionManager(section *originalSection, section *newSection) {
        originalSectionData.s = originalSection;
        newSectionData.s = newSection;
    }

    SectionManager() = default;

    void addSymbol(const Symbol &symbol) {
        originalSectionData.symbols.push_back(symbol);
    }

    void setRelocations(const std::vector<Relocation> &relocations) {
        originalSectionData.relocations = relocations;
    }

    std::string getName() const {
        if (originalSectionData.s == nullptr) {
            zerror("Couldn't get section name as it hasn't been initialized");
        }
        return originalSectionData.s->get_name();
    }

    void convertFunction(const Symbol &symbol,
                         const std::vector<Relocation> &relatedRelocations) {
        // get function data
        auto fAddress = symbol.value;
        auto fSize = symbol.size;

        // Skoki są zawsze w obrębie funkcji :) Więc jest gitt

        FunctionData fData(&originalSectionData.s->get_data()[fAddress], fSize,
                           symbol.value);

        auto rel = fData.convert(relatedRelocations);
        functions.push_back(fData);
        functionsRelocations.push_back(rel);
    }

    void convertFunctions() {
        std::sort(originalSectionData.symbols.begin(),
                  originalSectionData.symbols.end(),
                  [](const Symbol &s1, const Symbol &s2) -> bool {
                      return s1.value < s2.value;
                  });
        std::sort(originalSectionData.relocations.begin(),
                  originalSectionData.relocations.end(),
                  [](Relocation r1, Relocation r2) -> bool {
                      return r1.offset < r2.offset;
                  });

        for (const auto &symbol: originalSectionData.symbols) {
            if (symbol.type == STT_FUNC) {
                std::vector<Relocation> relatedRelocations;
                todo("Get related relocastions");
                convertFunction(symbol, relatedRelocations);
            } else {
                // TODO czy adresy symboli innych niż funkcje to może być
                // Rozumiem że adres funkcji może się zmienić
                // Ale czy może zmienić się adres czegoś innego niż funckja
                // Odpowiedź: tak, ale nie ma symboli w funkcji. pozostałe symbole
                // przesuwamy więc po prostu pod funkcjami
            }
        }

        todo("Construct section content from converted functions");
    }
};

class SymbolSectionManager {
    SectionManager s;

public:
    explicit SymbolSectionManager(const SectionManager &s) : s(s) {};

    SymbolSectionManager() = default;
};

class ConvertManager {
    elfio fileToConvert;
    elfio writer;
    // Indexes in original section header;
    std::map<Elf_Half, SectionManager> sectionManagers;

    // File symbol and external symbols
    std::vector<Symbol> globalSymbols;
    SymbolSectionManager symbolSectionManager;

    // https://stackoverflow.com/questions/874134/find-out-if-string-ends-with-another-string-in-c
    inline static bool ends_with(std::string const &value,
                                 std::string const &ending) {
        if (ending.size() > value.size())
            return false;
        return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
    }

    static bool isSkippable(const std::string &sectionName) {
        return sectionName == ".note.gnu.property" ||
               ends_with(sectionName, ".eh_frame");
    }

    int64_t identifySectionByName(const std::string &sectionName) const {
        mDebug << "finding " << sectionName << std::endl;
        for (const auto &sectionEntry: sectionManagers) {
            if (sectionEntry.second.getName() == sectionName) {
                return sectionEntry.first;
            }
        }
        mWarn << "Couldn't identify section by name" << std::endl;
        return -1;
    }

    static std::string
    getSectionNameFromRelocationSectionName(const std::string &relocationName) {
        assert(relocationName.substr(0, 5) == ".rela");
        return relocationName.substr(5);
    }

    void addSymbolsToSectionManager(section *symbolSection) {
        const symbol_section_accessor symbols(fileToConvert, symbolSection);

        mDebug << "Parsing symbol section" << std::endl;
        for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {
            Symbol s;
            Elf_Half sectionIndex;
            if (!symbols.get_symbol(j, s.name, s.value, s.size, s.bind, s.type,
                                    sectionIndex, s.other)) {
                zerror("Error getting symbol entry");
            }
            mDebug << s << std::endl;
            if (s.isGlobal(sectionIndex)) {
                mWarn << "symbol is global, will not do anything" << std::endl;
                globalSymbols.push_back(s);
            } else if (Symbol::isSpecial(sectionIndex)) {
                mWarn << "symbols from section " << sectionIndex << "are not handled "
                      << std::endl;
            } else {
                sectionManagers.find(sectionIndex)->second.addSymbol(s);
            }
        }
        symbolSectionManager = SymbolSectionManager(SectionManager(
                symbolSection, writer.sections.add(symbolSection->get_name())));
    }

    void addRelocationsToRelocationManager(section *relocationSection) {
        mDebug << "handling relocation section " << relocationSection->get_name()
               << std::endl;
        auto index = identifySectionByName(
                getSectionNameFromRelocationSectionName(relocationSection->get_name()));
        if (index < 0) {
            mWarn << "couldn't find section that the relocation section "
                  << relocationSection->get_name() << " relate to" << std::endl;
            return;
        }

        const relocation_section_accessor relocationSectionAccessor(
                fileToConvert, relocationSection);
        std::vector<Relocation> relocations;
        for (int i = 0; i < relocationSectionAccessor.get_entries_num(); i++) {
            Relocation r;
            if (!relocationSectionAccessor.get_entry(i, r.offset, r.symbol, r.type,
                                                     r.addend)) {
                zerror("Error getting relocation entry");
            }
            if (!Relocation::isRelocationHandled(r.type)) {
                mDebug << "relocation of this type is not handled" << std::endl;
            }
            relocations.push_back(r);
        }

        sectionManagers[index].setRelocations(relocations);
    }

    void parseSections() {
        mDebug << "Parsing begin" << std::endl;
        Elf_Half sec_num = fileToConvert.sections.size();

        // TODO associate all symbols and relocations with appropriate sections
        section *symbolSection;
        std::vector<section *> relocationSectionsToParse;
        mDebug << "Number of sections: " << sec_num << std::endl;
        for (int i = 0; i < sec_num; ++i) {
            section *psec = fileToConvert.sections[i];
            mDebug << " [" << i << "] " << psec->get_name() << "\t"
                   << psec->get_size() << std::endl;

            // https://stackoverflow.com/questions/3269590/can-elf-file-contain-more-than-one-symbol-table
            // There can be only one SYMTAB table
            if (psec->get_type() == SHT_SYMTAB) {
                symbolSection = psec;
            } else if (psec->get_type() == SHT_RELA) {
                relocationSectionsToParse.push_back(psec);
            } else if (!isSkippable(psec->get_name())) {
                // pomyśleć co z symbolami, które odnoszą się do usuniętych sekcji
                sectionManagers[i] =
                        SectionManager(psec, writer.sections.add(psec->get_name()));
            }
        }
        addSymbolsToSectionManager(symbolSection);
        for (auto r: relocationSectionsToParse) {
            addRelocationsToRelocationManager(r);
        }
        mDebug << "Section parsing ended" << std::endl;
    }

    void convertSections() {
        // 1. run capstone on each section data
        // 2. start converting one by one and updating details
        // There is need for interface that takes an address of instruction
        // beforehand nad converts it to address to instruction after

        // tabela rozmiarów instrukcji
    }

public:
    explicit ConvertManager(const std::string &path) {
        if (!fileToConvert.load(path)) {
            zerror("Couldn't find or process file");
        }
        if (!FileChecker::checkFile(fileToConvert)) {
            zerror("Error during checks on file");
        }
        parseSections();
        convertSections();
        // Access section's data
    }
};

#endif // CONVERTERPROJECT_CONVERTMANAGER_H
