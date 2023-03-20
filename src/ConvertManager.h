//
// Created by mateusz on 12.03.23.
//

#ifndef CONVERTERPROJECT_CONVERTMANAGER_H
#define CONVERTERPROJECT_CONVERTMANAGER_H


#include <elfio/elfio.hpp>
#include <map>
#include <cassert>
#include <ostream>
#include <optional>
#include "utils.h"

using namespace ELFIO;

#define mDebug (std::cout << "DEBUG: ")
#define mWarn (std::cout << "WARN: ")
#define todo(S) (zerror("TODO" S))
#define strEqual(I, J) (strcmp((I), (J)) == 0)


using address_t = Elf64_Addr;

class FileChecker {
public:
    static bool checkFile(const elfio &file);
};

struct Symbol {
private:
    static constexpr Elf_Word specialUnhandledSections[1] = {
            SHN_COMMON
    };
public:
    std::string name;
// Address in section
//    In relocatable files, st_value holds alignment constraints for a symbol whose section index is
//    SHN_COMMON.
//    In relocatable files, st_value holds a section offset for a defined symbol. That is, st_value is an
//    offset from the beginning of the section that st_shndx identifies.
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
        for (auto specialIndex: specialUnhandledSections) {
            if (specialIndex == sectionIndex) {
                return true;
            }
        }
        return false;
    }

    bool isFunction() {
        return type == STT_FUNC;
    }

    friend std::ostream &operator<<(std::ostream &os, const Symbol &symbol) {
        os << "name: " << symbol.name << " value: " << symbol.value << " size: " << symbol.size << " bind: "
           << symbol.bind << " type: " << symbol.type << " other: " << symbol.other;
        return os;
    }
};

class Relocation {
public:
    Elf64_Addr offset;
    Elf_Word symbol;
    unsigned type;
    Elf_Sxword addend;

    static bool isRelocationHandled(unsigned type) {
        return type == R_X86_64_PC32 |
               type == R_X86_64_PLT32 |
               type == R_X86_64_32 |
               type == R_X86_64_32S |
               type == R_X86_64_64;
    }

    Relocation() = default;

    friend std::ostream &operator<<(std::ostream &os, const Relocation &relocation) {
        os << "offset: " << relocation.offset << " symbol: " << relocation.symbol << " type: " << relocation.type
           << " addend: " << relocation.addend;
        return os;
    }
};


namespace assemblyUtils {
    const int ARM_INSTRUCTION_SIZE_BYTES = 32;
    std::string prefix64 = "x";
    std::string prefix32 = "w";
    std::string tmp1 = "12";
    std::string tmp2 = "13";

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

//    bool isRegister(std::string s) {
//        return registerMaps32.find(s) != registerMaps32.end() || registerMaps64.find(s) != registerMaps64.end();
//    }
//
//    bool isMem(std::string operand) {
//        return operand.find("[")  != std::string::npos;
//    }

    enum AddressMode {
        RegisterMode,
        ImmediateMode,
        MemoryMode
    };
}

//class AddressesCollector {
//    cs_insn *instructionIterator;
//public:
//    AddressesCollector(cs_insn *it)
//            : instructionIterator(it) {}
//
////    void convertInstruction() {
////        if (currentInstruction >= numberOfInstructions) {
////            zerror("All instruciton have been conerted");
////        }
////    }
//
//    size_t instructionSzie(size_t index) {
//        return instructionIterator[index].size;
//    }
//
//    address_t instructionAddress() {
//        return currentArmInstructionAddress;
//    }
//
//};

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
struct ConvertedInstruction {
    std::string content;
    size_t size;
    // !IMPORTANT Will have offsets relative to instruction address, not function address!
    std::vector<Relocation> changedRelocations;
};

namespace InstructionConverter {
    std::string mapRegister(x86_reg reg) {
        todo("Implement");
        return "";
    }

    std::string convert(cs_x86_op op) {
        if (op.type == x86_op_type::X86_OP_REG) {
            return mapRegister(op.reg);
        } else if (op.type == x86_op_type::X86_OP_IMM) {
            return std::to_string(op.imm);
        } else {
            todo("Unable to convert mem");
        }
    }

    ConvertedInstruction handleAdd(cs_insn *ins, const std::vector<Relocation> &relatedRelocations) {
        auto detail = ins->detail;
        assert(detail->x86.op_count == 2);
        assert(detail->x86.operands[0].type == x86_op_type::X86_OP_REG);
        assert(relatedRelocations.size() == 0);

        auto c = ConvertedInstruction{
                .content = "add " + InstructionConverter::convert(detail->x86.operands[0]) + ", " +
                           InstructionConverter::convert(detail->x86.operands[1]),
                .size = assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES,
        };
        return c;
    }

    ConvertedInstruction convertInstruction(cs_insn *ins, std::vector<Relocation> relatedRelocations) {
        ConvertedInstruction ret;
        if (strEqual(ins->mnemonic, "add")) {
            ret = handleAdd(ins, relatedRelocations);
        } else {
            todo("Implement getType");
        }

        return ret;
    }
};

struct JumpInstruction {
    size_t fromIndex;
    size_t toIndex;
};

class FunctionData {
    const int X64_PROLOGUE_SIZE = 3;
    const int X64_EPILOGUE_SIZE = 2;
    const int ARM_PROLOG_SIZE_BYTES = assemblyUtils::ARM_INSTRUCTION_SIZE_BYTES * 2;
    address_t baseAddress;

    CapstoneUtils utils;
    cs_insn *insn;
    size_t numberOfInstructions;

    bool converted;
    std::vector<std::string> armInstructions;
    std::vector<address_t> armInstructionAddresses;

    std::vector<JumpInstruction> jumps;

    // This will be needed for jumps
    size_t findInstructionByRelativeAddress(address_t x) {
        todo("Implement");
    }

    // TODO nie obsługuję skoczenia do ŚRODKA prologu (umiem skoczyć jedynie na początek)
    void convertPrologue() {
        assert(strEqual(insn[0].mnemonic, "endbr64"));
        assert(strEqual(insn[1].mnemonic, "push") && strEqual(insn[1].op_str, "rbp"));
        assert(strEqual(insn[2].mnemonic, "mov") && strEqual(insn[2].op_str, "rbp, rsp"));

        armInstructions.push_back("stp x29, x30, [sp, #-16]!\n"
                                  "mov x29, sp");

        // This is only for indexes
        armInstructions.push_back("");
        armInstructions.push_back("");

        armInstructionAddresses.push_back(0);
        armInstructionAddresses.push_back(ARM_PROLOG_SIZE_BYTES);
        armInstructionAddresses.push_back(ARM_PROLOG_SIZE_BYTES);
    }

    // TODO nie obsługuję skoczenia do ŚRODKA epilogu (umiem skoczyć jedynie na początek)
    void convertEpilogue() {
        assert(strEqual(insn[numberOfInstructions - 2].mnemonic, "leave"));
        assert(strEqual(insn[numberOfInstructions - 1].mnemonic, "ret"));

        armInstructions.push_back("mov x0, x9\n"
                                  "add sp, x29, #16\n"
                                  "ldp x29, x30, [sp, #-16]\n"
                                  "ret");
        armInstructions.push_back("");
    }

    static bool checkIfAddressBetweenInstruction(address_t offsetFromBase,
                                                 address_t instructionOffsetFromBase,
                                                 size_t instructionSize) {
        return offsetFromBase >= instructionOffsetFromBase &&
               offsetFromBase <= instructionOffsetFromBase + instructionSize;
    }

public:
    FunctionData(const char *rawData, size_t size, address_t baseAddress) {
//        raw.insert(raw.begin(), rawData, rawData + size);
        numberOfInstructions = utils.disassemble(reinterpret_cast<const uint8_t *>(rawData), size, insn);
        converted = false;
        baseAddress = baseAddress;
    }

    std::vector<Relocation> convert(std::vector<Relocation> relatedRelocations) {
        for (auto &r: relatedRelocations) {
            r.offset -= baseAddress;
        }

        convertPrologue();
        size_t currentRelocationIndex = 0;
        for (int i = X64_PROLOGUE_SIZE; i < numberOfInstructions - X64_EPILOGUE_SIZE; i++) {
            todo("Check if relocation is in this instruction");
            std::vector<Relocation> r;
            while (currentRelocationIndex < r.size() &&
                   checkIfAddressBetweenInstruction(relatedRelocations[currentRelocationIndex].offset,
                                                    insn[i].address,
                                                    insn[i].size)) {
                r.push_back(relatedRelocations[currentRelocationIndex]);
                currentRelocationIndex++;
            }
            auto c = InstructionConverter::convertInstruction(&insn[i], r);
            todo("Adjust relocations returned by converter - they are relative to instruction address, should be changed relative to section base address");
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

    void convertFunction(const Symbol &symbol, const std::vector<Relocation> &relatedRelocations) {
        // get function data
        auto fAddress = symbol.value;
        auto fSize = symbol.size;

        // Skoki są zawsze w obrębie funkcji :) Więc jest gitt

        FunctionData fData(&originalSectionData.s->get_data()[fAddress], fSize, symbol.value);

        auto rel = fData.convert(relatedRelocations);
        functions.push_back(fData);
        functionsRelocations.push_back(rel);
    }

    void convertFunctions() {
        std::sort(originalSectionData.symbols.begin(), originalSectionData.symbols.end(),
                  [](Symbol s1, Symbol s2) -> bool {
                      return s1.value < s2.value;
                  });
        std::sort(originalSectionData.relocations.begin(), originalSectionData.relocations.end(),
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
                // Odpowiedź: tak, ale nie ma symboli w funkcji. pozostałe symbole przesuwamy więc po prostu pod funkcjami
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
    inline static bool ends_with(std::string const &value, std::string const &ending) {
        if (ending.size() > value.size()) return false;
        return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
    }

    static bool isSkippable(const std::string &sectionName) {
        return sectionName == ".note.gnu.property" || ends_with(sectionName, ".eh_frame");
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

    static std::string getSectionNameFromRelocationSectionName(const std::string &relocationName) {
        assert(relocationName.substr(0, 5) == ".rela");
        return relocationName.substr(5);
    }


    void addSymbolsToSectionManager(section *symbolSection) {
        const symbol_section_accessor symbols(fileToConvert, symbolSection);


        mDebug << "Parsing symbol section" << std::endl;
        for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {
            Symbol s;
            Elf_Half sectionIndex;
            if (!symbols.get_symbol(j, s.name, s.value, s.size, s.bind,
                                    s.type, sectionIndex, s.other)) {
                zerror("Error getting symbol entry");
            }
            mDebug << s << std::endl;
            if (s.isGlobal(sectionIndex)) {
                mWarn << "symbol is global, will not do anything" << std::endl;
                globalSymbols.push_back(s);
            } else if (Symbol::isSpecial(sectionIndex)) {
                mWarn << "symbols from section " << sectionIndex << "are not handled " << std::endl;
            } else {
                sectionManagers.find(sectionIndex)->second.addSymbol(s);
            }
        }
        symbolSectionManager = SymbolSectionManager(
                SectionManager(symbolSection, writer.sections.add(symbolSection->get_name())));
    }

    void addRelocationsToRelocationManager(section *relocationSection) {
        mDebug << "handling relocation section " << relocationSection->get_name() << std::endl;
        auto index = identifySectionByName(getSectionNameFromRelocationSectionName(relocationSection->get_name()));
        if (index < 0) {
            mWarn << "couldn't find section that the relocation section " << relocationSection->get_name()
                  << " relate to" << std::endl;
            return;
        }

        const relocation_section_accessor relocationSectionAccessor(fileToConvert, relocationSection);
        std::vector<Relocation> relocations;
        for (int i = 0; i < relocationSectionAccessor.get_entries_num(); i++) {
            Relocation r{};
            if (!relocationSectionAccessor.get_entry(i, r.offset, r.symbol, r.type, r.addend)) {
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
            mDebug << " [" << i << "] " << psec->get_name() << "\t" << psec->get_size() << std::endl;

            // https://stackoverflow.com/questions/3269590/can-elf-file-contain-more-than-one-symbol-table
            // There can be only one SYMTAB table
            if (psec->get_type() == SHT_SYMTAB) {
                symbolSection = psec;
            } else if (psec->get_type() == SHT_RELA) {
                relocationSectionsToParse.push_back(psec);
            } else if (!isSkippable(psec->get_name())) {
                // pomyśleć co z symbolami, które odnoszą się do usuniętych sekcji
                sectionManagers[i] = SectionManager(psec, writer.sections.add(psec->get_name()));
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
        // There is need for interface that takes an address of instruction beforehand nad converts it to address to instruction after

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

#endif //CONVERTERPROJECT_CONVERTMANAGER_H
