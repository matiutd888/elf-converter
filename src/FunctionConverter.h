//
// Created by mateusz on 26.03.23.
//



#ifndef CONVERTERPROJECT_FUNCTIONCONVERTER_H
#define CONVERTERPROJECT_FUNCTIONCONVERTER_H

#include "ElfStructures.h"
#include "InstructionConverter.h"
#include <elfio/elfio.hpp>
#include <optional>
#include <queue>


class ConvertedFunctionData;
class FunctionConverter;

class ConvertedFunctionData {
    using ArmInstructionStubWithAddress =
            std::pair<ArmInstructionStub, address_t>;

    std::vector<ArmInstructionStubWithAddress> armInstructions;
    std::vector<JumpInstruction> jumps;
    std::vector<RelocationWithMAddress> armRels;

    size_t newFunctionAddress;

public:
    address_t getNewInstructionAddressInSection() const {
        if (armInstructions.empty()) {
            return newFunctionAddress;
        } else {
            return armInstructions.back().second +
                   armInstructions.back().first.sizeBytes;
        }
    }

    void addJump(const JumpInstruction &j) {
        jumps.push_back(j);
    }

    explicit ConvertedFunctionData(size_t newFunctionAddress) : newFunctionAddress(newFunctionAddress) {}

    void addArmInstruction(const ArmInstructionStub &a) {
        armInstructions.emplace_back(a, getNewInstructionAddressInSection());
    }

    const std::vector<JumpInstruction> &getJumps() const {
        return jumps;
    }

    address_t getAbsoluteAddressOfInstruction(size_t i) const {
        if (i < armInstructions.size()) {
            zerror("Instruction of such index doesn't exist: %zu", i);
        }
        return armInstructions[i].second;
    }

    void fixupArmInstruction(size_t index, const ArmInstructionStub &s) {
        armInstructions[index].first = s;
    };

    std::string getContent() const {
        std::string content;
        for (const auto &it: armInstructions) {
            content += it.first.content + "\n";
        }
        return content;
    }

    void addArmRel(size_t instructionAddressInSection, RelocationWithMAddress relocationWithMAddress) {
        relocationWithMAddress.maddress.setRelativeToSection(relocationWithMAddress.maddress.getRelativeToInstruction() + instructionAddressInSection);
        armRels.push_back(relocationWithMAddress);
    }

    size_t getFunctionSize() const {
        return getNewInstructionAddressInSection();
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
    const static std::string TEMPORARY_JUMP_INSTRUCTION_CONTENT;

    static const int X64_PROLOGUE_SIZE = 3;
    static const int X64_EPILOGUE_SIZE = 2;
    static const int ARM_PROLOG_SIZE_BYTES =
            AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 2;
    static const int ARM_EPILOGUE_SIZE_BYTES =
            AssemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 4;

    // TODO nie obsługuję skoczenia do ŚRODKA prologu (umiem skoczyć jedynie na
    // początek)
    static void convertPrologue(const FunctionData &f,
                                ConvertedFunctionData &data);

    static bool
    checkIfAddressBetweenInstruction(address_t offsetFromBase,
                                     address_t instructionOffsetFromBase,
                                     size_t instructionSize);

    // TODO nie obsługuję skoczenia do ŚRODKA epilogu (umiem skoczyć jedynie na
    // początek)
    static void convertEpilogue(const FunctionData &f,
                                ConvertedFunctionData &data);

    static void handleJumps(ConvertedFunctionData &data);;

public:
    static ConvertedFunctionData convert(size_t newFunctionBaseAddress, std::vector<ElfStructures::Relocation> relatedRelocations,
                                         const FunctionData &f);
};

#endif//CONVERTERPROJECT_FUNCTIONCONVERTER_H
