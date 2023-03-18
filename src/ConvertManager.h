//
// Created by mateusz on 12.03.23.
//

#ifndef CONVERTERPROJECT_CONVERTMANAGER_H
#define CONVERTERPROJECT_CONVERTMANAGER_H


#include <elfio/elfio.hpp>
#include <map>
#include <cassert>

using namespace ELFIO;


class FileChecker {
public:
    static bool checkFile(const elfio &file);
};

class Symbol {
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

    static bool isGlobal(Elf_Half sectionIndex) {
        return sectionIndex == SHN_UNDEF;
    }

    bool isFunction() {
        return type == STT_FUNC;
    }
};

// TODO think about jumps
class Relocation {
public:
    Elf64_Addr offset;
    Elf_Word symbol;
    unsigned type;
    Elf_Sxword addend;

    Relocation() = default;
};

struct SectionData {
    section *section = nullptr;
    std::vector<Symbol> symbols;
    std::vector<Relocation> relocations;
};


class SectionManager {
    SectionData originalSectionData;
    SectionData newSectionData;
public:
    explicit SectionManager(section *originalSection, section *newSection) {
        originalSectionData.section = originalSection;
        newSectionData.section = newSection;
    }

    SectionManager() = default;

    void addSymbol(const Symbol &symbol) {
        originalSectionData.symbols.push_back(symbol);
    }

    void setRelocations(const std::vector<Relocation> &relocations) {
        originalSectionData.relocations = relocations;
    }

    std::string getName() const {
        if (originalSectionData.section == nullptr) {
            perror("Coudln't get section name as it hasn't been initialized");
        }
        return originalSectionData.section->get_name();
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
    std::vector<Symbol> globalSymbols;
    SymbolSectionManager symbolSectionManager;

//    https://stackoverflow.com/questions/874134/find-out-if-string-ends-with-another-string-in-c
    inline static bool ends_with(std::string const &value, std::string const &ending) {
        if (ending.size() > value.size()) return false;
        return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
    }

    static bool isSkipable(const std::string &sectionName) {
        return sectionName == ".note.gnu.property" || ends_with(sectionName, ".eh_frame");
    }

    int64_t identifySectionByName(const std::string &sectionName) const {
        for (const auto &sectionEntry: sectionManagers) {
            if (sectionEntry.second.getName() == sectionName) {
                return sectionEntry.first;
            }
        }
        std::cerr << "Couldn't identify section by name" << std::endl;
        return -1;
    }

    static std::string getSectionNameFromRelocationSectionName(const std::string &relocationName) {
        assert(relocationName.substr(0, 5) == ".rela");
        return relocationName.substr(5);
    }

public:
    explicit ConvertManager(const std::string &path) {
        if (!fileToConvert.load(path)) {
            perror("Couldn't find or process file");
        }
        if (!FileChecker::checkFile(fileToConvert)) {
            perror("Error during checks on file");
        }
        parseSections();
        // Access section's data
    }

    void parseSections() {
        Elf_Half sec_num = fileToConvert.sections.size();

        // TODO associate all symbols and relocations with appropriate sections
        section *symbolSection;
        std::vector<section *> relocationSectionsToParse;
        std::cout << "Number of sections: " << sec_num << std::endl;
        for (int i = 0; i < sec_num; ++i) {
            section *psec = fileToConvert.sections[i];
            std::cout << " [" << i << "] " << psec->get_name() << "\t" << psec->get_size() << std::endl;
            // Access section's data
            const char *p = fileToConvert.sections[i]->get_data();

            // https://stackoverflow.com/questions/3269590/can-elf-file-contain-more-than-one-symbol-table
            // There can be only one SYMTAB table
            if (psec->get_type() == SHT_SYMTAB) {
                symbolSection = psec;
            } else if (psec->get_type() == SHT_RELA) {
                relocationSectionsToParse.push_back(psec);
            } else if (isSkipable(psec->get_name())) {
                // TODO pomyśleć co z symbolami, które odnoszą się do usuniętych sekcji
                sectionManagers[i] = SectionManager(psec, writer.sections.add(psec->get_name()));
            }
        }

        addSymbolsToSectionManager(symbolSection);
        for (auto r: relocationSectionsToParse) {
            addRelocationsToRelocationManager(r);
        }
    };


    void addSymbolsToSectionManager(section *symbolSection) {
        const symbol_section_accessor symbols(fileToConvert, symbolSection);
        for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {
            Symbol s;
            Elf_Half sectionIndex;
            if (!symbols.get_symbol(j, s.name, s.value, s.size, s.bind,
                                    s.type, sectionIndex, s.other)) {
                perror("Error getting symbol entry");
            }
            if (Symbol::isGlobal(sectionIndex)) {
                std::cout << "symbol is global, will not do anything" << std::endl;
                globalSymbols.push_back(s);
            } else {
                sectionManagers[sectionIndex].addSymbol(s);
            }
            std::cout << j << " " << s.name << std::endl;
        }
        symbolSectionManager = SymbolSectionManager(
                SectionManager(symbolSection, writer.sections.add(symbolSection->get_name())));
    }

    void addRelocationsToRelocationManager(section *relocationSection) {
        const relocation_section_accessor relocationSectionAccessor(fileToConvert, relocationSection);
        std::vector<Relocation> relocations;
        for (int i = 0; i < relocationSectionAccessor.get_entries_num(); i++) {
            Relocation r{};
            if (!relocationSectionAccessor.get_entry(i, r.offset, r.symbol, r.type, r.addend)) {
                perror("Error getting relocation entry");
            }
            relocations.push_back(r);
        }

        auto index = identifySectionByName(getSectionNameFromRelocationSectionName(relocationSection->get_name()));
        sectionManagers[index].setRelocations(relocations);
    }
};

#endif //CONVERTERPROJECT_CONVERTMANAGER_H
