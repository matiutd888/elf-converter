//
// Created by mateusz on 26.03.23.
//

#include "FunctionConverter.h"

const std::string FunctionConverter::TEMPORARY_JUMP_INSTRUCTION_CONTENT = "TEMPORARY-JUMP-CONTENT";

ConvertedFunctionData
FunctionConverter::convert(size_t newFunctionBaseAddress, std::vector<ElfStructures::Relocation> relatedRelocations,
                           const FunctionData &f) {
    assert(std::is_sorted(relatedRelocations.begin(),
                          relatedRelocations.end(),
                          [](ElfStructures::Relocation r1, ElfStructures::Relocation r2) -> bool {
                              return r1.offset < r2.offset;
                          }));

    mDebug << std::endl;
    mDebug << std::endl;
    mDebug << "----------------------------------" << std::endl;
    mDebug << "Converting function at address " << f.baseAddress << " with " << f.numberOfInstructions << std::endl;
    mDebug << "Function content" << std::endl;
    for (size_t i = 0; i < f.numberOfInstructions; i++) {
        printf("0x%" PRIx64":\t%s\t\t%s\n", f.insn[i].address, f.insn[i].mnemonic,
               f.insn[i].op_str);
    }
    mDebug << std::endl;
    mDebug << "End of function content" << std::endl;
    mDebug << "--------------------------------------" << std::endl;

    ConvertedFunctionData data(newFunctionBaseAddress);
    std::queue<RelocationWithMAddress> q;

    for (const auto &r: relatedRelocations) {
        RelocationWithMAddress rM(r);
        rM.maddress.setRelativeToSection(r.offset);
        rM.maddress.setRelativeToFunction(r.offset - f.baseAddress);
        q.push(rM);
    }

    convertPrologue(f, data);
    for (size_t i = X64_PROLOGUE_SIZE;
         i < f.numberOfInstructions - X64_EPILOGUE_SIZE; i++) {
        std::vector<RelocationWithMAddress> r;
        while (!q.empty() && checkIfAddressBetweenInstruction(
                q.front().maddress.getRelativeToFunction(),
                f.insn[i].address, f.insn[i].size)) {
            r.push_back(q.front());
            q.pop();
        }
        HandleInstrResult c =
                InstructionConverter::handleInstruction(&f.insn[i], r);
        switch (c.getType()) {
            case HandleInstrResult::JUMP_INSTRUCTION_TO_FILL_TYPE: {
                JumpInstructionToFill j = c.getJ();
                size_t toIndex = f.findInstructionByAddressFromBase(j.jmpImm);
                JumpInstruction jumpInstruction{
                        .fromIndex = i,
                        .toIndex = toIndex,
                        .jump = j};

                data.addJump(jumpInstruction);

                data.addArmInstruction(ArmInstructionStub(FunctionConverter::TEMPORARY_JUMP_INSTRUCTION_CONTENT, j.sizeBytes()));
                break;
            }
            case HandleInstrResult::ARM_INSTRUCTION_STUB_TYPE: {
                address_t newInstrAddressInSection = data.getNewInstructionAddressInSection();
                ArmStubWithRels_t armStubWithRels = c.getA();
                data.addArmInstruction(armStubWithRels.first);
                for (const auto &rel: armStubWithRels.second) {
                    data.addArmRel(newInstrAddressInSection, rel);
                }
                break;
            }
        }
    }
    convertEpilogue(f, data);
    handleJumps(data);
    return data;
}

void FunctionConverter::handleJumps(ConvertedFunctionData &data) {
    for (const auto &it: data.getJumps()) {
        address_t dstAbsoluteAddress = data.getAbsoluteAddressOfInstruction(it.toIndex);

        data.fixupArmInstruction(it.fromIndex, ArmInstructionStub(
                InstructionBuilder(it.jump.armMnemonic,
                                   AssemblyUtils::armUImmidiate(dstAbsoluteAddress))
                        .build(),
                JumpInstructionToFill::sizeBytes()));
    }
}

void FunctionConverter::convertEpilogue(const FunctionData &f, ConvertedFunctionData &data) {
    assert(strEqual(f.insn[f.numberOfInstructions - 2].mnemonic, "leave"));
    assert(strEqual(f.insn[f.numberOfInstructions - 1].mnemonic, "ret"));

    data.addArmInstruction(ArmInstructionStub("", 0));
    data.addArmInstruction(
            ArmInstructionStub(InstructionBuilder("mov", "x0", "x9")
                                       .append("add", "sp", "x29", "#16")
                                       .append("ldp", "x29", "x30", "[sp, #-16]")
                                       .append("ret")
                                       .build(),
                               ARM_EPILOGUE_SIZE_BYTES));
}

bool FunctionConverter::checkIfAddressBetweenInstruction(address_t offsetFromBase, address_t instructionOffsetFromBase,
                                                         size_t instructionSize) {
    return offsetFromBase >= instructionOffsetFromBase &&
           offsetFromBase <= instructionOffsetFromBase + instructionSize;
}

void FunctionConverter::convertPrologue(const FunctionData &f, ConvertedFunctionData &data) {
    assert(strEqual(f.insn[0].mnemonic, "endbr64"));
    assert(strEqual(f.insn[1].mnemonic, "push") &&
           strEqual(f.insn[1].op_str, "rbp"));
    assert(strEqual(f.insn[2].mnemonic, "mov") &&
           strEqual(f.insn[2].op_str, "rbp, rsp"));

    data.addArmInstruction(
            ArmInstructionStub(InstructionBuilder("stp x29, x30, [sp, #-16]!")
                                       .append("mov", "x29", "sp")
                                       .build(),
                               ARM_PROLOG_SIZE_BYTES));
    data.addArmInstruction(ArmInstructionStub("", 0));
    data.addArmInstruction(ArmInstructionStub("", 0));
}
