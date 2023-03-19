//
// Created by mateusz on 12.03.23.
//

#ifndef CONVERTERPROJECT_CONVERTMANAGER_H
#define CONVERTERPROJECT_CONVERTMANAGER_H


#include <elfio/elfio.hpp>
#include <map>
#include <cassert>
#include <ostream>
#include "utils.h"

using namespace ELFIO;

#define m_debug (std::cout << "DEBUG: ")
#define m_warn (std::cout << "WARN: ")
#define todo(S) (zerror("TODO" S))


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

// TODO think about jumps
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

#define strEqual(I, J) (strcmp((I), (J)) == 0)

class FunctionData {
    const int PROLOGUE_SIZE = 3;
    const int EPILOGUE_SIZE = 2;

    std::vector<char> raw;

    CapstoneUtils utils;
    cs_insn *insn;
    size_t numberOfInstructions;

    bool converted;
    std::vector<char *> convertedBytes;
    std::vector<std::string> armInstructions;


    // TODO nie obsługuję skoczenia do ŚRODKA prologu (umiem skoczyć jedynie na początek)
    void convertPrologue() {
        assert(strEqual(insn[0].mnemonic, "endbr64"));
        assert(strEqual(insn[1].mnemonic, "push") && strEqual(insn[1].op_str, "rbp"));
        assert(strEqual(insn[2].mnemonic, "mov") && strEqual(insn[2].op_str, "rbp, rsp"));

        armInstructions.push_back("stp x29, x30, [sp, #-16]!\n"
                                  "mov x29, sp");
    }

    // TODO nie obsługuję skoczenia do ŚRODKA epilogu (umiem skoczyć jedynie na początek)
    void convertEpilogue() {
        assert(strEqual(insn[numberOfInstructions - 2].mnemonic, "leave"));
        assert(strEqual(insn[numberOfInstructions - 1].mnemonic, "ret"));

        armInstructions.push_back("mov x0, x9\n"
                                  "add sp, x29, #16\n"
                                  "ldp x29, x30, [sp, #-16]\n"
                                  "ret");
    }

public:
    FunctionData(const char *rawData, size_t size) {
        raw.insert(raw.begin(), rawData, rawData + size);
        numberOfInstructions = utils.disassemble(reinterpret_cast<const uint8_t *>(raw[0]), raw.size(), insn);
        converted = false;
    }


    void convertInstruction(cs_insn *insn) {

    }

    std::vector<Relocation> convert(std::vector<Relocation> relatedRelocations) {
        convertPrologue();
        for (int i = PROLOGUE_SIZE; i < numberOfInstructions - EPILOGUE_SIZE; i++) {
            todo("Check if relocation is in this instruction");

            convertInstruction(&insn[i]);
        }
        convertEpilogue();
        todo("Use capstone to be able to answer queries about addresses");
        convertEpilogue();
    }


    size_t getNewAddress(size_t oldAddress) {
        if (!converted) {
            zerror("Function hasn't been converted yet");
        }
        todo("Implement");
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

    void convertFunction(const Symbol &symbol, std::vector<Relocation> relatedRelocations) {
        // get function data
        auto fAddress = symbol.value;
        auto fSize = symbol.size;

        // Skoki są zawsze w obrębie funkcji :) Więc jest gitt

        FunctionData fData(&originalSectionData.s->get_data()[fAddress], fSize);

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
                // Ale czy może zmienić się adres czegoś innego niż
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
        m_debug << "finding " << sectionName << std::endl;
        for (const auto &sectionEntry: sectionManagers) {
            if (sectionEntry.second.getName() == sectionName) {
                return sectionEntry.first;
            }
        }
        m_warn << "Couldn't identify section by name" << std::endl;
        return -1;
    }

    static std::string getSectionNameFromRelocationSectionName(const std::string &relocationName) {
        assert(relocationName.substr(0, 5) == ".rela");
        return relocationName.substr(5);
    }


    void addSymbolsToSectionManager(section *symbolSection) {
        const symbol_section_accessor symbols(fileToConvert, symbolSection);


        m_debug << "Parsing symbol section" << std::endl;
        for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {
            Symbol s;
            Elf_Half sectionIndex;
            if (!symbols.get_symbol(j, s.name, s.value, s.size, s.bind,
                                    s.type, sectionIndex, s.other)) {
                zerror("Error getting symbol entry");
            }
            m_debug << s << std::endl;
            if (s.isGlobal(sectionIndex)) {
                m_warn << "symbol is global, will not do anything" << std::endl;
                globalSymbols.push_back(s);
            } else if (Symbol::isSpecial(sectionIndex)) {
                m_warn << "symbols from section " << sectionIndex << "are not handled " << std::endl;
            } else {
                sectionManagers.find(sectionIndex)->second.addSymbol(s);
            }
        }
        symbolSectionManager = SymbolSectionManager(
                SectionManager(symbolSection, writer.sections.add(symbolSection->get_name())));
    }

    void addRelocationsToRelocationManager(section *relocationSection) {
        m_debug << "handling relocation section " << relocationSection->get_name() << std::endl;
        auto index = identifySectionByName(getSectionNameFromRelocationSectionName(relocationSection->get_name()));
        if (index < 0) {
            m_warn << "couldn't find section that the relocation section " << relocationSection->get_name()
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
                m_debug << "relocation of this type is not handled" << std::endl;
            }
            relocations.push_back(r);
        }

        sectionManagers[index].setRelocations(relocations);
    }

    void parseSections() {
        m_debug << "Parsing begin" << std::endl;
        Elf_Half sec_num = fileToConvert.sections.size();

        // TODO associate all symbols and relocations with appropriate sections
        section *symbolSection;
        std::vector<section *> relocationSectionsToParse;
        m_debug << "Number of sections: " << sec_num << std::endl;
        for (int i = 0; i < sec_num; ++i) {
            section *psec = fileToConvert.sections[i];
            m_debug << " [" << i << "] " << psec->get_name() << "\t" << psec->get_size() << std::endl;

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
        m_debug << "Section parsing ended" << std::endl;
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
