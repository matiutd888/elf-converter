//
// Created by mateusz on 26.03.23.
//

#ifndef CONVERTERPROJECT_FUNCTIONCONVERTER_H
#define CONVERTERPROJECT_FUNCTIONCONVERTER_H


#include "ElfStructures.h"
#include "InstructionConverter.h"
#include <elfio/elfio.hpp>
#include <optional>


class FunctionConverter;

class ConvertedFunctionData {
    friend FunctionConverter;
    using ArmInstructionStubWithAddress =
            std::pair<ArmInstructionStub, address_t>;

    std::vector<ArmInstructionStubWithAddress> armInstructions;
    std::vector<JumpInstruction> jumps;
    std::vector<RelocationWithMAddress> armRels;

    address_t getNewInstructionAddress() const {
        if (armInstructions.empty()) {
            return 0;
        } else {
            return armInstructions.back().second +
                   armInstructions.back().first.sizeBytes;
        }
    }

    void addArmInstruction(const ArmInstructionStub &a) {
        armInstructions.emplace_back(a, getNewInstructionAddress());
    }

public:
    std::string getContent() const {
        std::string content;
        for (const auto &it: armInstructions) {
            content += it.first.content + "\n";
        }
        return content;
    }
    size_t getFunctionSize() const {
        return getNewInstructionAddress();
    }

    const std::vector<RelocationWithMAddress> &getRelocations() const {
        return armRels;
    }
};

class FunctionData {
    friend FunctionConverter;
    const address_t baseAddress;

    cs_insn *insn;
    unsigned long numberOfInstructions;

    // This will be needed for jumps
    size_t findInstructionByAddressFromBase(address_t addressFromBase) const {
        size_t it = 0;
        while (it < numberOfInstructions && addressFromBase > insn[it].address) {
            it++;
        }
        if (it == numberOfInstructions) {
            zerror("Unable to find instruction by address");
        }
        if (insn[it].address != addressFromBase) {
            zerror("Jump is not to the beinning of instruction");
        }
        return it;
    }

public:
    FunctionData(const char *rawData, size_t size, address_t baseAddress)
        : insn(nullptr), baseAddress(baseAddress),
          numberOfInstructions(CapstoneUtils::getInstance().disassemble(
                  reinterpret_cast<const uint8_t *>(rawData), size, &insn)) {}

    // This probably will not be neccessaru
    //  address_t getNewAddress(address_t oldAddress) {
    //    if (!converted) {
    //      zerror("Function hasn't been converted yet");;
    //    }
    //  }
};

class FunctionConverter {
    static const int X64_PROLOGUE_SIZE = 3;
    static const int X64_EPILOGUE_SIZE = 2;
    static const int ARM_PROLOG_SIZE_BYTES =
            assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 2;
    static const int ARM_EPILOGUE_SIZE_BYTES =
            assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 4;

    // TODO nie obsługuję skoczenia do ŚRODKA prologu (umiem skoczyć jedynie na
    // początek)
    static void convertPrologue(const FunctionData &f,
                                ConvertedFunctionData &data) {
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

    static bool
    checkIfAddressBetweenInstruction(address_t offsetFromBase,
                                     address_t instructionOffsetFromBase,
                                     size_t instructionSize) {
        return offsetFromBase >= instructionOffsetFromBase &&
               offsetFromBase <= instructionOffsetFromBase + instructionSize;
    }

    // TODO nie obsługuję skoczenia do ŚRODKA epilogu (umiem skoczyć jedynie na
    // początek)
    static void convertEpilogue(const FunctionData &f,
                                ConvertedFunctionData &data) {
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

    static void handleJumps(ConvertedFunctionData &data) {
        for (const auto &it: data.jumps) {
            address_t dstAbsoluteAddress = data.armInstructions[it.toIndex].second;
            address_t srcAbsoluteAddress = data.armInstructions[it.fromIndex].second;

            // TODO czy ta konwersja jest dobra.
            int64_t difference =
                    int64_t(dstAbsoluteAddress) - int64_t(srcAbsoluteAddress);
            data.armInstructions[it.fromIndex].first = ArmInstructionStub(
                    InstructionBuilder(it.jump.armMnemonic,
                                       assemblyUtils::armImmidiate(difference))
                            .build(),
                    JumpInstructionToFill::sizeBytes());
        }
    };

    static address_t getRip(cs_insn *ins) { return ins->address + ins->size; }

public:
    static ConvertedFunctionData convert(std::vector<Relocation> relatedRelocations,
                                         const FunctionData &f) {
        assert(std::is_sorted(relatedRelocations.begin(),
                              relatedRelocations.end(),
                              [](Relocation r1, Relocation r2) -> bool {
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

        ConvertedFunctionData data;
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
                    size_t toIndex =
                            f.findInstructionByAddressFromBase(j.jmpImm + getRip(&f.insn[i]));
                    JumpInstruction jumpInstruction{
                            .fromIndex = i,
                            .toIndex = toIndex,
                            .jump = j};

                    data.jumps.push_back(jumpInstruction);

                    data.addArmInstruction(ArmInstructionStub("", j.sizeBytes()));
                    break;
                }
                case HandleInstrResult::ARM_INSTRUCTION_STUB_TYPE: {
                    address_t newInstrAddress = data.getNewInstructionAddress();
                    ArmStubWithRels_t armStubWithRels = c.getA();
                    data.addArmInstruction(armStubWithRels.first);
                    for (auto &rel: armStubWithRels.second) {
                        rel.maddress.setRelativeToFunction(
                                rel.maddress.getRelativeToInstruction() + newInstrAddress);
                    }
                    data.armRels.insert(data.armRels.end(), armStubWithRels.second.begin(),
                                        armStubWithRels.second.end());
                    break;
                }
            }
        }
        convertEpilogue(f, data);
        handleJumps(data);
        return data;
    }
};

#endif//CONVERTERPROJECT_FUNCTIONCONVERTER_H
