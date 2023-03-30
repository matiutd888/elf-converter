//
// Created by mateusz on 12.03.23.
//

#ifndef CONVERTERPROJECT_CONVERTMANAGER_H
#define CONVERTERPROJECT_CONVERTMANAGER_H

#include "AssemblyUtils.h"
#include "ElfStructures.h"
#include "FunctionConverter.h"
#include "InstructionConverter.h"
#include "Utils.h"
#include <algorithm>
#include <cassert>
#include <elfio/elfio.hpp>
#include <map>
#include <optional>
#include <ostream>
#include <queue>
#include <variant>

using namespace ELFIO;

class SectionBuilder {
    ElfStructures::SectionData data;
    std::vector<unsigned char> bytes;
    size_t sSize;
public:
    void copyMetaData(section *originalSection) const {
        data.s->set_type(originalSection->get_type());
        data.s->set_flags(originalSection->get_flags());
        data.s->set_addr_align(originalSection->get_addr_align());
        data.s->set_info(originalSection->get_info());
    }

    size_t sectionSize() const {
        return sSize;
    }

    explicit SectionBuilder(section *newSection, std::optional<section *> relatedRelocationSection) {
        data.s = newSection;
        data.relatedRelocationsection = relatedRelocationSection;
        sSize = 0;
    }

    void addConvertedFunctionData(const ElfStructures::Symbol &originalSymbol, const ConvertedFunctionData &fData);

    void addNonFunctionChunk(size_t size, address_t originalChunkAddress, unsigned char const *chunkBytes,
                             const std::vector<ElfStructures::Symbol> &relatedSymbols,
                             const std::vector<ElfStructures::Relocation> &relatedRelocations);

    void setSectionSymbol(ElfStructures::Symbol s) {
        assert(s.isSection());
        s.sectionIndex = data.s->get_index();
        data.sectionSymbol = s;
        mDebug << "SECTION SYMBOL SET " << data.sectionSymbol.value() << std::endl;
    }

    ElfStructures::SectionData setDataAndBuild() {
        if (data.s->get_type() == SHT_NOBITS) {
            data.s->set_data(nullptr, sectionSize());
        } else {
            data.s->set_data(reinterpret_cast<const char *>(bytes.data()), sectionSize());
        }
        return data;
    }
};

class SectionManager {
    ElfStructures::SectionData originalSectionData;

    static std::vector<ElfStructures::Relocation>
    getRelatedRelocations(const std::vector<ElfStructures::Relocation> &relocations, const size_t chunkStart,
                          size_t chunkEnd) {
        std::vector<ElfStructures::Relocation> relatedRelocations;
        for (const auto &it: relocations) {
            if (it.offset >= chunkStart && it.offset <= chunkEnd) {
                relatedRelocations.push_back(it);
            }
        }
        return relatedRelocations;
    }

public:
    explicit SectionManager(section *originalSection) {
        originalSectionData.s = originalSection;
    }

    SectionManager() = default;

    void addSymbol(const ElfStructures::Symbol &symbol) {
        if (symbol.isSection()) {
            mDebug << "Adding section symbol " << symbol << std::endl;
            originalSectionData.sectionSymbol = symbol;
        } else if (symbol.isSymbolWithLocation()) {
            originalSectionData.symbolsWithLocations.push_back(symbol);
        } else {
            mWarn << "SectionManager: Symbol " << symbol << " is not handled" << std::endl;
        }
    }

    void setRelocations(const std::vector<ElfStructures::Relocation> &relocations, section *relocationSection) {
        originalSectionData.relocations = relocations;
        originalSectionData.relatedRelocationsection = relocationSection;
    }

    std::string getName() const {
        if (originalSectionData.s == nullptr) {
            zerror("Couldn't get section name as it hasn't been initialized");
        }
        return originalSectionData.s->get_name();
    }

    const ElfStructures::SectionData &getOriginalSectionData() const {
        return originalSectionData;
    }


    ElfStructures::SectionData convert(elfio &writer);

    section *getOriginalSection() const {
        return originalSectionData.s;
    };
};

class ConvertedFileBuilder {
    elfio writer;
    Elf_Word maxLocalIndex = 0;

public:
    ConvertedFileBuilder() {
        writer.create(ELFCLASS64, ELFDATA2LSB);
        // TODO czy tutaj nie powinno być ELFOSABI_ARM
        writer.set_os_abi(ELFOSABI_LINUX);
        writer.set_type(ET_REL);
        writer.set_machine(EM_AARCH64);
    }

    elfio &getWriter() {
        return writer;
    }

    void addSymbol(std::map<Elf_Word, Elf_Word> &tableIndexMappng, const ElfStructures::Symbol &s,
                   symbol_section_accessor &syma, string_section_accessor &stra) {
        Elf_Word newIndex = syma.add_symbol(stra, s.name.c_str(), s.value, s.size, s.bind, s.type, s.other,
                                            s.sectionIndex);
        mDebug << "Adding symbol: [" << newIndex << "] " << s << std::endl;
        tableIndexMappng[s.tableIndex] = newIndex;

        if (s.bind == STB_LOCAL) {
            maxLocalIndex = std::max(maxLocalIndex, newIndex + 1);
        }
    }

    void addSectionSymbol(std::map<Elf_Word, Elf_Word> &tableIndexMapping, const ElfStructures::Symbol &s, symbol_section_accessor &syma) {
        // Set string table index to 0.
        auto newIndex = syma.add_symbol(0, s.value, s.size, s.bind, s.type, s.other, s.sectionIndex);
        mDebug << "Adding symbol: [" << newIndex << "] " << s.value << std::endl;
        tableIndexMapping[s.tableIndex] = newIndex;

        if (s.bind == STB_LOCAL) {
            maxLocalIndex = std::max(maxLocalIndex, newIndex + 1);
        }
    }

    void buildElfFile(const std::vector<ElfStructures::SectionData> &sectionDatas,
                      const std::vector<ElfStructures::Symbol> &externalSymbols, const section *originalSymbolSection);

    void save(const std::string &name) {
        writer.save(name);
    }
};

class ConvertManager {
    elfio fileToConvert;
    // Indexes in original section header;
    std::map<Elf_Half, SectionManager> sectionManagers;

    // File symbol and external symbols
    std::vector<ElfStructures::Symbol> externalSymbols;
    std::optional<size_t> symbolSectionIndex;


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

    void addSymbolsToSectionManager() {
        if (!symbolSectionIndex.has_value()) {
            zerror("Symbol section wan't parsed yet!");
        }
        auto it = sectionManagers.find(symbolSectionIndex.value());
        if (it == sectionManagers.end()) {
            zerror("Unexpected error getting symbol section");
        }
        const symbol_section_accessor symbols(fileToConvert, it->second.getOriginalSection());

        mDebug << "Parsing symbol section" << std::endl;
        for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {
            ElfStructures::Symbol s;
            s.tableIndex = j;
            if (!symbols.get_symbol(j, s.name, s.value, s.size, s.bind, s.type,
                                    s.sectionIndex, s.other)) {
                zerror("Error getting symbol entry");
            }
            mDebug << s << std::endl;
            if (s.shouldNotBeHandled()) {
                mWarn << "symbols from section " << s.sectionIndex << "are not handled " << std::endl;
            } else if (s.isExternal()) {
                mDebug << "symbol is external, will not do anything" << std::endl;
                externalSymbols.push_back(s);
            } else {
                auto sit = sectionManagers.find(s.sectionIndex);
                if (sit != sectionManagers.end()) {
                    sit->second.addSymbol(s);
                } else {
                    mWarn << "Coudln't find section that symbol refers to - index " << s.sectionIndex << std::endl;
                }
            }
        }
    }

    void addRelocationsToRelocationManager(size_t relSectionIndex) {
        section *relocationSection = sectionManagers.find(relSectionIndex)->second.getOriginalSection();
        mDebug << "handling relocation section " << relocationSection->get_name()
               << std::endl;
        auto index = relocationSection->get_info();
        if (sectionManagers.find(index) == sectionManagers.end()) {
            mWarn << "couldn't find section that the relocation section "
                  << relocationSection->get_name() << " relate to" << std::endl;
            return;
        }

        const relocation_section_accessor relocationSectionAccessor(
                fileToConvert, relocationSection);
        std::vector<ElfStructures::Relocation> relocations;
        for (size_t i = 0; i < relocationSectionAccessor.get_entries_num(); i++) {
            ElfStructures::Relocation r;
            if (!relocationSectionAccessor.get_entry(i, r.offset, r.symbol, r.type,
                                                     r.addend)) {
                zerror("Error getting relocation entry");
            }
            if (!ElfStructures::Relocation::isRelocationHandled(r.type)) {
                mDebug << "relocation of this type is not handled" << std::endl;
            }
            relocations.push_back(r);
        }
        assert(sectionManagers.find(index) != sectionManagers.end());
        sectionManagers.find(index)->second.setRelocations(relocations, relocationSection);
        mDebug << "relocation handled successfully" << std::endl;
    }

    void parseSections() {
        mDebug << "Parsing begin" << std::endl;
        Elf_Half sec_num = fileToConvert.sections.size();

        std::vector<size_t> relocationSectionsToParse;
        mDebug << "Number of sections: " << sec_num << std::endl;
        for (size_t i = 0; i < sec_num; ++i) {
            section *psec = fileToConvert.sections[i];
            mDebug << " [" << i << "] " << psec->get_name() << "\t"
                   << psec->get_size() << std::endl;

            if (isSkippable(psec->get_name())) {
                continue;
            }
            // https://stackoverflow.com/questions/3269590/can-elf-file-contain-more-than-one-symbol-table
            // There can be only one SYMTAB table
            if (psec->get_type() == SHT_SYMTAB) {
                symbolSectionIndex = i;
            } else if (psec->get_type() == SHT_RELA) {
                relocationSectionsToParse.push_back(i);
            }
            sectionManagers.insert({i, SectionManager(psec)});
        }
        addSymbolsToSectionManager();
        for (auto r: relocationSectionsToParse) {
            addRelocationsToRelocationManager(r);
        }
        mDebug << "Section parsing ended" << std::endl;
    }

    void printParsedData() {
        mDebug << std::endl;
        mDebug << "---------------------------" << std::endl;
        mDebug << "printing parsed elf file" << std::endl;
        mDebug << "global symbols " << std::endl;
        for (const auto &s : externalSymbols) {
            mDebug << s << std::endl;
        }
        mDebug << std::endl;
        mDebug << "sections" << std::endl;
        for (const auto &s : sectionManagers) {
            mDebug << std::endl;
            mDebug << "[" << s.first << "]" << s.second.getName() << std::endl;
            mDebug << "---- related symbols:" << std::endl;
            if (s.second.getOriginalSectionData().sectionSymbol.has_value()) {
                mDebug << "section symbol " << s.second.getOriginalSectionData().sectionSymbol.value() << std::endl;
            } else {
                mDebug << "section doesn't have section symbol" << std::endl;
            }
            for (const auto &sym : s.second.getOriginalSectionData().symbolsWithLocations) {
                mDebug << sym << std::endl;
            }
            mDebug << "/-- related symbols END" << std::endl;
            mDebug << "--- related relocations" << std::endl;
            for (const auto &r : s.second.getOriginalSectionData().relocations) {
                mDebug << r << std::endl;
            }
            mDebug << "/-- related rels END" << std::endl;
            mDebug << "/-- section END" << std::endl;
        }
        mDebug << "/------ END PARSED DATA" << std::endl;
    }

public:
    explicit ConvertManager(const std::string &path) {
        if (!fileToConvert.load(path)) {
            zerror("Couldn't find or process file");
        }
        parseSections();
        printParsedData();
    }

    void convert(const std::string &outputFile) {
        mDebug << "starting conversion" << std::endl;

        ConvertedFileBuilder builder;
        std::vector<ElfStructures::SectionData> convertedSections;
        // todo jeśli na qemu będą dodawane symbole każdej sekcji (w tym sekcji relokacji oraz symboli)
        // to będzie trzeba te symbole rówbnież przekaząźć builderowi
        for (auto &it: sectionManagers) {
            mDebug << it.first << ": ";
            if (it.second.getOriginalSection()->get_index() == SHN_UNDEF) {
                mDebug << "not converting null section " << std::endl;
            } else if (it.second.getOriginalSection()->get_type() == SHT_SYMTAB) {
                mDebug << "not converting symtab section " << std::endl;
            } else if (it.second.getOriginalSection()->get_type() == SHT_RELA) {
                mDebug << "not converting relocation section " << it.second.getName() << std::endl;
            } else if (it.second.getOriginalSection()->get_type() == SHT_STRTAB) {
                mDebug << "not converting string section " << it.second.getOriginalSection()->get_data() << " " << it.second.getOriginalSection()->get_index() << std::endl;
            } else {
                mDebug << "converting section " << it.second.getOriginalSection()->get_index() <<  std::endl;
                convertedSections.push_back(it.second.convert(builder.getWriter()));
            }
        }
        builder.buildElfFile(convertedSections, externalSymbols,
                             sectionManagers.find(symbolSectionIndex.value())->second.getOriginalSection());
        builder.save(outputFile);
    }
};

#endif// CONVERTERPROJECT_CONVERTMANAGER_H
