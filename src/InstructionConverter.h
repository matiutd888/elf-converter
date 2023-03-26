//
// Created by mateusz on 26.03.23.
//


using address_t = ELFIO::Elf64_Addr;

#ifndef CONVERTERPROJECT_INSTRUCTIONCONVERTER_H
#define CONVERTERPROJECT_INSTRUCTIONCONVERTER_H

#include "AssemblyUtils.h"
#include "ConvertManager.h"
#include <algorithm>
#include <cassert>
#include <string>
#include <variant>

#define strEqual(I, J) (strcmp((I), (J)) == 0)

struct ArmInstructionStub {
    static void sizeAssert(const std::string &content, size_t size) {
        if (content.empty()) {
            assert(size == 0);
        } else {
            assert(size % AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES == 0);
            assert(std::count(content.begin(), content.end(), '\n') + 1 ==
                   size / AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES);
        }
    }

public:
    std::string content;
    size_t sizeBytes;

    ArmInstructionStub(const std::string &content, size_t size)
        : content(content), sizeBytes(size) {

        sizeAssert(content, size);
    }
};

// TODO refactor this terrible class
class InstructionBuilder {
    // Lord forvie me for O(n^2) complexity of this code
    std::string ret;

    static std::string makeInstr(const std::string &instruction,
                                 const std::string &arg1, const std::string &arg2,
                                 const std::string &arg3) {
        return instruction + " " + arg1 + ", " + arg2 + ", " + arg3;
    }

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

    InstructionBuilder append(const std::string &instruction) {
        return InstructionBuilder(ret + "\n" + instruction);
    }

    InstructionBuilder append(const std::string &instruction,
                              const std::string &arg1) {
        return  InstructionBuilder(ret + "\n" + makeInstr(instruction, arg1));
    }

    InstructionBuilder append(const std::string &instruction,
                              const std::string &arg1, const std::string &arg2) {
        return InstructionBuilder(ret + "\n" + makeInstr(instruction, arg1, arg2));
    }

    InstructionBuilder append(const std::string &instruction,
                              const std::string &arg1, const std::string &arg2,
                              const std::string &arg3) {
        return InstructionBuilder(ret + "\n" + makeInstr(instruction, arg1, arg2, arg3));
    }

    std::string build() { return ret; }
};


class MAddress {
    std::optional<address_t> relativeToSection;
    std::optional<address_t> relativeToInstruction;
    std::optional<address_t> relativeToFunction;

public:
    void setRelativeToFunction(address_t rFunction) {
        this->relativeToFunction = rFunction;
    }

    void setRelativeToSection(address_t rSection) {
        this->relativeToSection = rSection;
    }

    void setRelativeToInstruction(address_t rInstruction) {
        this->relativeToInstruction = rInstruction;
    }

    address_t getRelativeToFunction() const { return relativeToFunction.value(); }

    address_t getRelativeToInstruction() const {
        return relativeToInstruction.value();
    }

    address_t getRelativeToSection() const {
        return relativeToSection.value();
    }
};

class RelocationWithMAddress {
    ElfStructures::Relocation r;

public:
    MAddress maddress;

    unsigned type() const { return r.type; };

    Elf_Word symbol() const { return r.symbol; }

    Elf_Sxword addend() const { return r.addend; }

    explicit RelocationWithMAddress(const ElfStructures::Relocation &r) : r(r) {}
};


using ArmStubWithRels_t =
        std::pair<ArmInstructionStub, std::vector<RelocationWithMAddress>>;

ArmStubWithRels_t createArmStubWithRels(const ArmInstructionStub &a,
                                        const std::vector<ElfStructures::Relocation> &rel) {
    std::vector<RelocationWithMAddress> r;
    std::transform(rel.begin(), rel.end(), std::back_inserter(r),
                   [](ElfStructures::Relocation r) -> RelocationWithMAddress {
                       auto ret = RelocationWithMAddress(r);
                       ret.maddress.setRelativeToInstruction(r.offset);
                       return ret;
                   });

    return {a, r};
}

ArmStubWithRels_t createArmStubWithRels(const ArmInstructionStub &a) {
    return {a, std::vector<RelocationWithMAddress>()};
}


namespace InstructionConverterUtils {
    void commonMemAsserts(x86_op_mem mem) { assert(mem.index == 0); }

    ArmStubWithRels_t convertNonRelocableMemOperand(AssemblyUtils::TmpKind tmp1Kind,
                                                    x86_op_mem op,
                                                    const reg_t &reg) {
        reg_t tmp164 =
                AssemblyUtils::getTmpRegByMemOpSize(tmp1Kind, AssemblyUtils::MEM64);
        return createArmStubWithRels(ArmInstructionStub(
                InstructionBuilder("mov", tmp164, AssemblyUtils::armImmidiate(op.disp))
                        .append(
                                "ldr", reg,
                                AssemblyUtils::armMemOp(AssemblyUtils::armReg(op.base), tmp164))
                        .build(),
                AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 2));
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
    // rip + (adresSymbolu - (adresInstrukcji + operandPositionInInstruction) +
    // addend) = adresSymbolu - operandPositionInInstruction + addend + (rip -
    // adresInstrukcji) = adresSymbolu - operandPositionInInstruction + addend +
    // ROZMIAR_INSTRUKCJI_x86 i do tego samego adresu sami musimy się odnieść w
    // armie. instrukcja ldr z liczbą x odnosi się do adresu pc + x a relokacja
    // R_AARCH64_LD_PREL_LO19 ma wartość relokowaną (adresSymbolu + addend -
    // offsetRelokacji) W armie offsetRelokacji jest równy adresowi instrukcji,
    // czyli PC. więc relokacja ostatecaznie będzie się odnosić do (adresSymbolu +
    // addend - PC) + PC (dodaje PC bo taka jest semantyka ldr) = adresSymbolu +
    // addend W takim wypadku relokacja w armie (która ma adres równy adresowi
    // instrukcji) powinna mieć taki addendArm, że  będzie równy temu do czego
    // odnosił się pierowtny operand, czyli adresSymbolu  + addendArm = adresSymbolu
    // - operandPositionInInstruction + addendx86 + ROZMIAR_INSTRUKCJI_x86 Z tego
    // mamy: addendArm = addendx86 - operandPositionInInstruction +
    // ROZMIAR_INSTRUKCJI_x86
    // https://reverseengineering.stackexchange.com/questions/17666/how-does-the-ldr-instruction-work-on-arm
    // Wczytaj op do reg
    ArmStubWithRels_t
    convertRelocableMemOperand(const reg_t &reg, const RelocationWithMAddress &rel,
                               size_t operandPositionInInstruction,
                               size_t x86InsSize) {
        ElfStructures::Relocation retRel(0, rel.symbol(), R_AARCH64_LD_PREL_LO19,
                          rel.addend() + (Elf_Sword) x86InsSize -
                                  (Elf_Sword) operandPositionInInstruction);
        return createArmStubWithRels(
                ArmInstructionStub(
                        InstructionBuilder("ldr", reg, AssemblyUtils::armImmidiate(0))
                                .build(),
                        AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES),
                {retRel});
    }

    // relocationPositionInInstruction
    // if operand is [rip + x], what byte is x in in the instruction
    // example: cmp qword ptr [rip + _], 2137 would have relocation for the byte 3
    // cmp qword ptr [rip + _], 2137 would be having relocation for byte 2
    // TODO maybe tmpToUse should ALWAYS be tmp1
    // It doesnt hurt us even when reg is tmp1 probably
    ArmStubWithRels_t readMemOpToReg(
            const std::vector<RelocationWithMAddress> &relocations, const reg_t &reg,
            x86_op_mem op, cs_insn *ins,
            AssemblyUtils::TmpKind tmpToUse// tmpToUse is index of free tmp register
                                           // this probably can be read from
                                           // relocations[0].offset - ins->address
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
}// namespace InstructionConverterUtils


class JumpInstructionToFill {
    static const size_t SIZE = AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES;

public:
    reg_t armMnemonic;
    int64_t jmpImm;

    JumpInstructionToFill(const reg_t &mnemonic, int64_t jmpImm)
        : armMnemonic(mnemonic), jmpImm(jmpImm) {}

    static size_t sizeBytes() { return SIZE; }
};

class HandleInstrResult {
    std::variant<ArmStubWithRels_t, JumpInstructionToFill> content;

public:
    static const size_t ARM_INSTRUCTION_STUB_TYPE = 0;
    static const size_t JUMP_INSTRUCTION_TO_FILL_TYPE = 1;

    explicit HandleInstrResult(
            const std::variant<ArmStubWithRels_t, JumpInstructionToFill> &a)
        : content(a) {}

    size_t getType() const { return content.index(); }

    size_t size() {
        if (getType() == ARM_INSTRUCTION_STUB_TYPE) {
            const ArmInstructionStub &a = std::get<ArmStubWithRels_t>(content).first;
            return a.sizeBytes;
        } else if (getType() == JUMP_INSTRUCTION_TO_FILL_TYPE) {
            return std::get<JumpInstructionToFill>(content).sizeBytes();
        } else {
            zerror("Wrong type of HandleInstrResult");
        }
    }

    JumpInstructionToFill getJ() const {
        return std::get<JumpInstructionToFill>(content);
    }

    ArmStubWithRels_t getA() const {
        return std::get<ArmStubWithRels_t>(content);
    }
};

namespace InstructionConverter {
    using namespace InstructionConverterUtils;

    namespace cmpHandler {
        namespace {
            ArmStubWithRels_t
            handleCmpReg(cs_insn *ins,
                         const std::vector<RelocationWithMAddress> &relatedRelocations) {
                switch (ins->detail->x86.operands[1].type) {
                    case X86_OP_REG:
                    case X86_OP_IMM:
                        return createArmStubWithRels(ArmInstructionStub(
                                InstructionBuilder(
                                        "cmp", AssemblyUtils::armConvertOp(ins->detail->x86.operands[0]),
                                        AssemblyUtils::armConvertOp(ins->detail->x86.operands[1]))
                                        .build(),
                                AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES));
                    case X86_OP_MEM: {
                        x86_op_mem m = ins->detail->x86.operands[1].mem;
                        auto memOpSize = AssemblyUtils::getMemOpSize(ins->detail->x86.operands[1]);
                        reg_t tmp =
                                AssemblyUtils::getTmpRegByMemOpSize(AssemblyUtils::TMP1, memOpSize);
                        auto c =
                                readMemOpToReg(relatedRelocations, tmp, m, ins, AssemblyUtils::TMP2);
                        c.first.sizeBytes += AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES;
                        c.first.content =
                                InstructionBuilder(c.first.content)
                                        .append("cmp",
                                                AssemblyUtils::armConvertOp(ins->detail->x86.operands[0]),
                                                tmp)
                                        .build();
                        return c;
                    }
                    default:
                        zerror("handleCmpReg: Invalid second operand");
                }
            }

            ArmStubWithRels_t
            handleCmpMem(cs_insn *ins,
                         const std::vector<RelocationWithMAddress> &relatedRelocations) {
                x86_op_mem m = ins->detail->x86.operands[0].mem;
                auto memOpSize = AssemblyUtils::getMemOpSize(ins->detail->x86.operands[0]);
                reg_t tmp =
                        AssemblyUtils::getTmpRegByMemOpSize(AssemblyUtils::TMP1, memOpSize);
                auto c = readMemOpToReg(relatedRelocations, tmp, m, ins, AssemblyUtils::TMP2);
                c.first.sizeBytes += AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES;
                c.first.content =
                        InstructionBuilder(c.first.content)
                                .append("cmp", tmp,
                                        AssemblyUtils::armConvertOp(ins->detail->x86.operands[1]))
                                .build();
                return c;
            }

        }// namespace

        ArmStubWithRels_t
        handleCmp(cs_insn *ins,
                  const std::vector<RelocationWithMAddress> &relatedRelocations) {
            assert(ins->detail->x86.op_count == 2);
            assert(relatedRelocations.empty());
            switch (ins->detail->x86.operands[0].type) {
                case X86_OP_REG:
                    return handleCmpReg(ins, relatedRelocations);
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
                    return handleCmpMem(ins, relatedRelocations);
                default:
                    zerror("cmp: Invalid operand type");
            }
        }
    }// namespace cmpHandler

    namespace movHandler {
        namespace {
            ArmStubWithRels_t
            handleMovReg(cs_insn *ins,
                         const std::vector<RelocationWithMAddress> &relatedRelocations) {
                switch (ins->detail->x86.operands[1].type) {
                    case x86_op_type::X86_OP_MEM:
                        return readMemOpToReg(
                                relatedRelocations,
                                AssemblyUtils::armReg(ins->detail->x86.operands[0].reg),
                                ins->detail->x86.operands[1].mem, ins, AssemblyUtils::TMP1);
                    case x86_op_type::X86_OP_IMM:
                        if (!relatedRelocations.empty() &&
                            (relatedRelocations[0].type() == R_X86_64_32 ||
                             relatedRelocations[0].type() == R_X86_64_32S)) {

                            // Addendu nie zmieniamy, bo relokacja nie jest relatywna
                            ElfStructures::Relocation r(0, relatedRelocations[0].symbol(), R_AARCH64_ADR_PREL_LO21,
                                         relatedRelocations[0].addend());
                            auto instr =
                                    InstructionBuilder("adr",
                                                       AssemblyUtils::convertRegisterMemSize(
                                                               AssemblyUtils::X86_64, AssemblyUtils::MEM64,
                                                               CapstoneUtils::getInstance().getRegName(ins->detail->x86.operands[0].reg)),
                                                       AssemblyUtils::armImmidiate(0))
                                            .build();
                            return createArmStubWithRels(
                                    ArmInstructionStub(instr, AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES),
                                    {r});
                        } else {
                            break;
                        }
                    case x86_op_type::X86_OP_REG:
                        break;
                    default:
                        zerror("Error handling mov");
                }
                return createArmStubWithRels(
                        {InstructionBuilder(
                                 "mov", AssemblyUtils::armConvertOp(ins->detail->x86.operands[0]),
                                 AssemblyUtils::armConvertOp(ins->detail->x86.operands[1]))
                                 .build(),
                         AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES});
            }

            ArmStubWithRels_t handleMovMemNonRipBase(
                    cs_insn *ins,
                    const std::vector<RelocationWithMAddress> &relatedRelocations) {
                auto mem = ins->detail->x86.operands[0].mem;
                switch (ins->detail->x86.operands[1].type) {
                    case X86_OP_IMM: {
                        if (!relatedRelocations.empty() &&
                            (relatedRelocations[0].type() == R_X86_64_32 ||
                             relatedRelocations[0].type() == R_X86_64_32S)) {

                            // Addendu nie zmieniamy, bo w nierelatywnych (R_X86_64_32, R_X86_64_32S)
                            // relokacjach położenie określane było przez po prostu adres symbolu +
                            // addend
                            ElfStructures::Relocation r =
                                    ElfStructures::Relocation(0, relatedRelocations[0].symbol(), R_AARCH64_ADR_PREL_LO21,
                                               relatedRelocations[0].addend());
                            auto tmp164 = AssemblyUtils::getTmpRegByMemOpSize(AssemblyUtils::TMP1,
                                                                              AssemblyUtils::MEM64);
                            auto tmp264 = AssemblyUtils::getTmpRegByMemOpSize(AssemblyUtils::TMP2,
                                                                              AssemblyUtils::MEM64);
                            auto instr =
                                    InstructionBuilder("adr", tmp164, AssemblyUtils::armImmidiate(0))
                                            .append("mov", tmp264, AssemblyUtils::armImmidiate(mem.disp))
                                            .append(
                                                    "str",
                                                    AssemblyUtils::getTmpRegByMemOpSize(
                                                            AssemblyUtils::TMP1, AssemblyUtils::getMemOpSize(ins->detail->x86.operands[0])),
                                                    AssemblyUtils::armMemOp(AssemblyUtils::armReg(mem.base),
                                                                            tmp264))
                                            .build();
                            return createArmStubWithRels(
                                    ArmInstructionStub(instr,
                                                       AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 3),
                                    {r});
                        }
                    }
                    case X86_OP_REG:
                        break;
                    default:
                        zerror("handleMovMemNonRipBase: Invalid operand type");
                }
                auto tmp1 = AssemblyUtils::getTmpRegByMemOpSize(
                        AssemblyUtils::TMP1, AssemblyUtils::getMemOpSize(ins->detail->x86.operands[0]));
                auto tmp264 = AssemblyUtils::getTmpRegByMemOpSize(AssemblyUtils::TMP2,
                                                                  AssemblyUtils::MEM64);
                auto instr = InstructionBuilder(
                                     "mov", tmp1,
                                     AssemblyUtils::armConvertOp(ins->detail->x86.operands[1]))
                                     .append("mov", tmp264, AssemblyUtils::armImmidiate(mem.disp))
                                     .append("str", tmp1,
                                             AssemblyUtils::armMemOp(
                                                     AssemblyUtils::armReg(mem.base), tmp264))
                                     .build();
                return createArmStubWithRels(
                        {instr, AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 3});
            }

            ArmStubWithRels_t handleMovMemRipBase(
                    cs_insn *ins,
                    const std::vector<RelocationWithMAddress> &relatedRelocations) {
                assert(relatedRelocations.size() == 1);
                assert(relatedRelocations[0].type() == R_X86_64_PC32 ||
                       relatedRelocations[0].type() == R_X86_64_PLT32);
                size_t relocationOffsetInInstruction =
                        relatedRelocations[0].maddress.getRelativeToFunction() - ins->address;
                Elf_Sxword newAddend = relatedRelocations[0].addend() +
                                       (Elf_Sxword) ins->size -
                                       (Elf_Sxword) relocationOffsetInInstruction;
                ElfStructures::Relocation r = ElfStructures::Relocation(0, relatedRelocations[0].symbol(),
                                          R_AARCH64_ADR_PREL_LO21, newAddend);
                reg_t tmp2 = AssemblyUtils::getTmpRegByMemOpSize(
                        AssemblyUtils::TMP2, AssemblyUtils::getMemOpSize(ins->detail->x86.operands[0]));
                reg_t tmp164 = AssemblyUtils::getTmpRegByMemOpSize(AssemblyUtils::TMP1,
                                                                   AssemblyUtils::MEM64);
                auto instr =
                        InstructionBuilder("adr", tmp164, AssemblyUtils::armImmidiate(0))
                                .append("mov", tmp2,
                                        AssemblyUtils::armConvertOp(ins->detail->x86.operands[1]))
                                .append("str", tmp2, AssemblyUtils::armMemOp(tmp164))
                                .build();
                return createArmStubWithRels(
                        ArmInstructionStub(instr, 3 * AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES),
                        {r});
            }

            ArmStubWithRels_t
            handleMovMem(cs_insn *ins,
                         const std::vector<RelocationWithMAddress> &relatedRelocations) {
                auto m = ins->detail->x86.operands[0].mem;
                commonMemAsserts(ins->detail->x86.operands[0].mem);
                switch (m.base) {
                    case X86_REG_RIP:
                        return handleMovMemRipBase(ins, relatedRelocations);
                    default:
                        return handleMovMemNonRipBase(ins, relatedRelocations);
                }
            }

        }// namespace

        ArmStubWithRels_t
        handleMov(cs_insn *ins,
                  const std::vector<RelocationWithMAddress> &relatedRelocations) {
            assert(ins->detail->x86.op_count = 2);
            switch (ins->detail->x86.operands[0].type) {
                case x86_op_type::X86_OP_REG:
                    return handleMovReg(ins, relatedRelocations);
                case x86_op_type::X86_OP_MEM:
                    return handleMovMem(ins, relatedRelocations);
                default:
                    zerror("mov: Incorrect first operand type: %d", ins->detail->x86.operands[0]
                                                                            .type);
            }
        }
    }// namespace movHandler

    namespace callHandler {
        ArmStubWithRels_t
        handleCall(cs_insn *ins,
                   const std::vector<RelocationWithMAddress> &relatedRelocations) {
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
            ElfStructures::Relocation r = ElfStructures::Relocation(0, relatedRelocations[0].symbol(), R_AARCH64_CALL26,
                                      relatedRelocations[0].addend() + 4);
            return createArmStubWithRels(
                    ArmInstructionStub(
                            InstructionBuilder("bl", AssemblyUtils::armImmidiate(0))
                                    .append("mov", "x9", "x0")
                                    .build(),
                            AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 2),
                    {r});
        }
    }// namespace callHandler

    namespace arithmeticInstructionHandler {
        ArmStubWithRels_t
        handleAdd(cs_insn *ins,
                  const std::vector<RelocationWithMAddress> &relatedRelocations) {
            assert(ins->detail->x86.op_count == 2);
            assert(ins->detail->x86.operands[0].type == x86_op_type::X86_OP_REG);
            assert(relatedRelocations.empty());

            return

                    createArmStubWithRels(ArmInstructionStub(
                            InstructionBuilder(
                                    "add", AssemblyUtils::armConvertOp(ins->detail->x86.operands[0]),
                                    AssemblyUtils::armConvertOp(ins->detail->x86.operands[1]))
                                    .build(),
                            AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES

                            ));
        }

        ArmStubWithRels_t
        handleSub(cs_insn *ins,
                  const std::vector<RelocationWithMAddress> &relatedRelocations) {
            assert(ins->detail->x86.op_count == 2);
            assert(ins->detail->x86.operands[0].type == x86_op_type::X86_OP_REG);
            assert(relatedRelocations.empty());

            return createArmStubWithRels(ArmInstructionStub(
                    InstructionBuilder(
                            "sub", AssemblyUtils::armConvertOp(ins->detail->x86.operands[0]),
                            AssemblyUtils::armConvertOp(ins->detail->x86.operands[1]))
                            .build(),
                    AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES));
        }

    }// namespace arithmeticInstructionHandler

    namespace jmpHandler {
        namespace {
            std::map<std::string, std::string> conditionalMap = {
                    {"a", "hi"},
                    {"ae", "hs"},
                    {"b", "lo"},
                    {"be", "ls"},
                    {"e", "eq"},
                    {"g", "gt"},
                    {"ge", "ge"},
                    {"l", "lt"},
                    {"le", "le"},
                    {"na", "ls"},
                    {"nae", "lo"},
                    {"nb", "hs"},
                    {"nbe", "hi"},
                    {"ne", "ne"},
                    {"ng", "le"},
                    {"nge", "lt"},
                    {"nl", "ge"},
                    {"nle", "gt"},
                    {"no", "vc"},
                    {"nz", "ne"},
                    {"o", "vs"},
                    {"z", "eq"},
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

        JumpInstructionToFill
        handleJmp(cs_insn *ins,
                  const std::vector<RelocationWithMAddress> &relatedRelocations) {
            assert(ins->detail->x86.op_count == 1);
            assert(relatedRelocations.empty());
            assert(ins->detail->x86.operands[0].type == X86_OP_IMM);

            return JumpInstructionToFill("b", ins->detail->x86.operands[0].imm);
        }

        JumpInstructionToFill handleConditionalJmp(
                cs_insn *ins,
                const std::vector<RelocationWithMAddress> &relatedRelocations) {
            assert(ins->detail->x86.op_count == 1);
            assert(relatedRelocations.empty());
            assert(ins->detail->x86.operands[0].type == X86_OP_IMM);

            std::string mnemonic = std::string(ins->mnemonic);
            std::string armSuffix = conditionalMap[mnemonic.substr(1)];
            return JumpInstructionToFill("b" + armSuffix,
                                         ins->detail->x86.operands[0].imm);
        }
    }// namespace jmpHandler

    HandleInstrResult handleInstruction(
            cs_insn *ins,
            const std::vector<RelocationWithMAddress> &relatedRelocations) {
        if (strEqual(ins->mnemonic, "add")) {
            return HandleInstrResult(
                    arithmeticInstructionHandler::handleAdd(ins, relatedRelocations));
        } else if (strEqual(ins->mnemonic, "sub")) {
            return HandleInstrResult(
                    arithmeticInstructionHandler::handleSub(ins, relatedRelocations));
        } else if (strEqual(ins->mnemonic, "cmp")) {
            return HandleInstrResult(cmpHandler::handleCmp(ins, relatedRelocations));
        } else if (strEqual(ins->mnemonic, "call")) {
            return HandleInstrResult(callHandler::handleCall(ins, relatedRelocations));
        } else if (strEqual(ins->mnemonic, "mov")) {
            return HandleInstrResult(movHandler::handleMov(ins, relatedRelocations));
        } else if (strEqual(ins->mnemonic, "jmp")) {
            return HandleInstrResult(jmpHandler::handleJmp(ins, relatedRelocations));
        } else if (jmpHandler::isConditionalJump(ins->mnemonic)) {
            return HandleInstrResult(
                    jmpHandler::handleConditionalJmp(ins, relatedRelocations));
        }
    }// namespace InstructionConverter
}// namespace InstructionConverter

struct JumpInstruction {
    size_t fromIndex;
    size_t toIndex;
    JumpInstructionToFill jump;
};


#endif//CONVERTERPROJECT_INSTRUCTIONCONVERTER_H
