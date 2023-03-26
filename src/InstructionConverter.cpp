#include "InstructionConverter.h"
//
// Created by mateusz on 26.03.23.
//
ArmStubWithRels_t InstructionConverterUtils::convertRelocableMemOperand(const reg_t &reg, const RelocationWithMAddress &rel, size_t operandPositionInInstruction, size_t x86InsSize) {
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
ArmStubWithRels_t InstructionConverterUtils::readMemOpToReg(const std::vector<RelocationWithMAddress> &relocations, const reg_t &reg, x86_op_mem op, cs_insn *ins, AssemblyUtils::TmpKind tmpToUse) {
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
ArmStubWithRels_t InstructionConverterUtils::convertNonRelocableMemOperand(AssemblyUtils::TmpKind tmp1Kind, x86_op_mem op, const reg_t &reg) {
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
void InstructionConverterUtils::commonMemAsserts(x86_op_mem mem) { assert(mem.index == 0); }

HandleInstrResult InstructionConverter::handleInstruction(cs_insn *ins, const std::vector<RelocationWithMAddress> &relatedRelocations) {
    JmpHandler jmpHandler;

    if (strEqual(ins->mnemonic, "add")) {
        return HandleInstrResult(
                ArithmeticInstructionHandler().handleAdd(ins, relatedRelocations));
    } else if (strEqual(ins->mnemonic, "sub")) {
        return HandleInstrResult(
                ArithmeticInstructionHandler().handleSub(ins, relatedRelocations));
    } else if (strEqual(ins->mnemonic, "cmp")) {
        return HandleInstrResult(CmpHandler().handleCmp(ins, relatedRelocations));
    } else if (strEqual(ins->mnemonic, "call")) {
        return HandleInstrResult(CallHandler().handleCall(ins, relatedRelocations));
    } else if (strEqual(ins->mnemonic, "mov")) {
        return HandleInstrResult(MovHandler().handleMov(ins, relatedRelocations));
    } else if (strEqual(ins->mnemonic, "jmp")) {
        return HandleInstrResult(jmpHandler.handleJmp(ins, relatedRelocations));
    } else if (jmpHandler.isConditionalJump(ins->mnemonic)) {
        return HandleInstrResult(
                jmpHandler.handleConditionalJmp(ins, relatedRelocations));
    }
}
