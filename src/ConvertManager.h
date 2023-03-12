//
// Created by mateusz on 12.03.23.
//

#ifndef CONVERTERPROJECT_CONVERTMANAGER_H
#define CONVERTERPROJECT_CONVERTMANAGER_H


#include <elfio/elfio.hpp>
#include <map>

using namespace ELFIO;


class FileChecker {
public:
    static bool checkFile(const elfio &file);
};

class Symbol {
public:
    std::string name;
    // Address in section
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

class Relocation {

};

class SectionManager {
    section *newSection;
    section *originalSection;
    std::vector<Symbol> originalSymbolsInSection;
    std::vector<Relocation> relocationsInSection;
public:
    explicit SectionManager(section *originalSection, section *newSection) : originalSection(originalSection),
                                                                             newSection(newSection) {}

    SectionManager() = default;

    void addOriginalSymbol(const Symbol &symbol) {
        originalSymbolsInSection.push_back(symbol);
    }
};

class SymbolSectionManager {
    SectionManager s;
public:
    explicit SymbolSectionManager(const SectionManager &s) : s(s) {};

    SymbolSectionManager() = default;
};

class RelocationSectionManager {
    SectionManager s;
public:
    explicit RelocationSectionManager(const SectionManager &s) : s(s) {};

    RelocationSectionManager() = default;
};


class ConvertManager {
    elfio fileToConvert;
    elfio writer;
    std::map<size_t, SectionManager> newSections;
    std::vector<section *> original_sections;
    std::vector<Symbol> globalSymbols;
    SymbolSectionManager symbolSectionManager;
    RelocationSectionManager relocationSectionManager;

//    https://stackoverflow.com/questions/874134/find-out-if-string-ends-with-another-string-in-c
    inline static bool ends_with(std::string const &value, std::string const &ending) {
        if (ending.size() > value.size()) return false;
        return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
    }

    static bool isSkipable(const std::string &sectionName) {
        return sectionName == ".note.gnu.property" || ends_with(sectionName, ".eh_frame");
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
        section *relocationSection;
        std::cout << "Number of sections: " << sec_num << std::endl;
        for (int i = 0; i < sec_num; ++i) {
            section *psec = fileToConvert.sections[i];
            std::cout << " [" << i << "] " << psec->get_name() << "\t" << psec->get_size() << std::endl;
            // Access section's data
            const char *p = fileToConvert.sections[i]->get_data();

            if (psec->get_type() == SHT_SYMTAB) {
                symbolSection = psec;
                const symbol_section_accessor symbols(fileToConvert, psec);
                for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {

                    Symbol s;
                    Elf_Half sectionIndex;
                    symbols.get_symbol(j, s.name, s.value, s.size, s.bind,
                                       s.type, sectionIndex, s.other);
                    if (Symbol::isGlobal(sectionIndex)) {
                        std::cout << "symbol is global, will not do anything" << std::endl;
                    }

                    std::cout << j << " " << s.name << std::endl;
                }
            } else if (psec->get_type() == SHT_RELA) {
                relocationSection = psec;
            } else if (isSkipable(psec->get_name())) {
                // TODO pomyśleć co z symbolami, które odnoszą się do usuniętych sekcji
                newSections[i] = SectionManager(psec, writer.sections.add(psec->get_name()));
            }
        }
    };
};

#endif //CONVERTERPROJECT_CONVERTMANAGER_H
