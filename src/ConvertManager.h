//
// Created by mateusz on 12.03.23.
//

#ifndef CONVERTERPROJECT_CONVERTMANAGER_H
#define CONVERTERPROJECT_CONVERTMANAGER_H

#include "AssemblyUtils.h"
#include "ElfStructures.h"
#include "FunctionConverter.h"
#include "InstructionConverter.h"
#include "utils.h"
#include <algorithm>
#include <cassert>
#include <elfio/elfio.hpp>
#include <map>
#include <optional>
#include <ostream>
#include <queue>
#include <variant>

using namespace ELFIO;

#define mDebug (std::cout << "DEBUG: ")
#define mWarn (std::cout << "WARN: ")
#define todo(S) zerror("TODO: " S)

// TODO więcej assertów do relokacji / braku relokajci?

class FileChecker {
public:
    static bool checkFile(const elfio &file);
};

class SectionBuilder {
    SectionData data;
    std::vector<unsigned char> bytes;

public:
    void copyMetaData(section *originalSection) const {
        data.s->set_type(originalSection->get_type());
        data.s->set_flags(originalSection->get_flags());
        data.s->set_addr_align(originalSection->get_addr_align());
        data.s->set_info(originalSection->get_info());
    }

    size_t sectionSize() const {
        return bytes.size();
    }

    explicit SectionBuilder(section *newSection, std::optional<section *> relatedRelocationSection) {
        data.s = newSection;
        data.relatedRelocationsection = relatedRelocationSection;
    }

    void addConvertedFunctionData(const Symbol &originalSymbol, const ConvertedFunctionData &fData) {
        address_t functionAddress = bytes.size();
        size_t fSize = fData.getFunctionSize();
        std::string content = fData.getContent();

        mDebug << "---------------------------------" << std::endl;
        mDebug << "Adding converted function data" << std::endl;
        mDebug << std::endl;
        mDebug << "function content: " << std::endl;
        mDebug << content << std::endl;
        mDebug << "End of function content" << std::endl;
        mDebug << "-----------------------------" << std::endl;


        for (const auto &it: fData.getRelocations()) {
            MAddress addr = it.maddress;
            addr.setRelativeToSection(addr.getRelativeToFunction() + functionAddress);
            data.relocations.emplace_back(addr.getRelativeToSection(), it.symbol(), it.type(), it.addend());
        }

        {
            unsigned char *encoded;
            size_t count;
            size_t keystoneSize;
            KeystoneUtils::getInstance().assemble(content.c_str(), &encoded, keystoneSize, count);
            assert(keystoneSize == fSize);

            for (int i = 0; i < keystoneSize; i++) {
                bytes.push_back(encoded[i]);
            }
            free(encoded);
        }
        Symbol newFSymbol = originalSymbol;
        newFSymbol.value = functionAddress;
        newFSymbol.size = fSize;

        data.symbolsWithLocations.push_back(newFSymbol);
    }

    void addNonFunctionChunk(size_t size, address_t originalChunkAddress, unsigned char const *chunkBytes,
                             const std::vector<Symbol> &relatedSymbols,
                             const std::vector<Relocation> &relatedRelocations) {

        address_t newChunkAddress = sectionSize();
        Elf_Sxword diff = (Elf_Sxword) newChunkAddress - (Elf_Sxword) originalChunkAddress;
        for (const auto &s: relatedSymbols) {
            Symbol newS = s;
            assert(newS.type == STT_NOTYPE || newS.type == STT_OBJECT);
            newS.value += diff;
            data.symbolsWithLocations.push_back(newS);
        }
        for (const auto &rel: relatedRelocations) {
            Relocation newRel = rel;
            newRel.offset += diff;
            assert(rel.type == R_X86_64_64);
            newRel.type = R_AARCH64_ABS64;
            data.relocations.push_back(newRel);
        }
        for (size_t i = 0; i < size; i++) {
            bytes.push_back(chunkBytes[i]);
        }
    }

    void setSectionSymbol(const Symbol &s) {
        assert(s.isSection());
        data.sectionSymbol = s;
    }

    SectionData setDataAndBuild() {
        data.s->set_data(reinterpret_cast<const char *>(bytes.data()), bytes.size());
        return data;
    }
};

class SectionManager {
    SectionData originalSectionData;

    static std::vector<Relocation> getRelatedRelocations(const std::vector<Relocation> &relocations, const size_t chunkStart, size_t chunkEnd) {
        std::vector<Relocation> relatedRelocations;
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

    void addSymbol(const Symbol &symbol) {
        if (symbol.isSection()) {
            originalSectionData.sectionSymbol = symbol;
        } else if (symbol.isSymbolWithLocation()) {
            originalSectionData.symbolsWithLocations.push_back(symbol);
        } else {
            mWarn << "SectionManager: Symbol " << symbol << " is not handled" << std::endl;
        }
    }

    void setRelocations(const std::vector<Relocation> &relocations, section *relocationSection) {
        originalSectionData.relocations = relocations;
        originalSectionData.relatedRelocationsection = relocationSection;
    }

    std::string getName() const {
        if (originalSectionData.s == nullptr) {
            zerror("Couldn't get section name as it hasn't been initialized");
        }
        return originalSectionData.s->get_name();
    }

    SectionData convert(elfio &writer) {
        section *newSection = writer.sections.add(originalSectionData.s->get_name());
        SectionBuilder newSectionBuilder(newSection, originalSectionData.relatedRelocationsection);
        newSectionBuilder.copyMetaData(originalSectionData.s);

        if (originalSectionData.sectionSymbol.has_value()) {
            newSectionBuilder.setSectionSymbol(originalSectionData.sectionSymbol.value());
        }

        std::sort(originalSectionData.symbolsWithLocations.begin(),
                  originalSectionData.symbolsWithLocations.end(),
                  [](const Symbol &s1, const Symbol &s2) -> bool {
                      return s1.value < s2.value;
                  });
        std::sort(originalSectionData.relocations.begin(),
                  originalSectionData.relocations.end(),
                  [](Relocation r1, Relocation r2) -> bool {
                      return r1.offset < r2.offset;
                  });
        auto symbolsIt = originalSectionData.symbolsWithLocations.cbegin();


        size_t chunkStart = 0;
        bool end = false;
        while (!end) {
            std::vector<Symbol> chunkSymbols;
            size_t chunkEnd;
            std::optional<Symbol> function;
            while (symbolsIt != originalSectionData.symbolsWithLocations.end() && !symbolsIt->isFunction()) {
                chunkSymbols.push_back(*symbolsIt);
                symbolsIt++;
            }
            if (symbolsIt != originalSectionData.symbolsWithLocations.end()) {
                function = *symbolsIt;
                chunkEnd = symbolsIt->value;
            } else {
                end = true;
                chunkEnd = originalSectionData.s->get_size();
            }

            size_t chunkSize = chunkEnd - chunkStart;
            newSectionBuilder.addNonFunctionChunk(chunkSize,
                                                  chunkStart,
                                                  reinterpret_cast<const unsigned char *>(&originalSectionData.s->get_data()[chunkStart]),
                                                  chunkSymbols,
                                                  getRelatedRelocations(originalSectionData.relocations, chunkStart, chunkEnd));

            if (function.has_value()) {
                address_t functionEndAddress = function->value + function->size;
                chunkStart = functionEndAddress;
                const FunctionData fData(&originalSectionData.s->get_data()[function->value], function->size, function->value);
                newSectionBuilder.addConvertedFunctionData(function.value(),
                                                           FunctionConverter::convert(getRelatedRelocations(originalSectionData.relocations, function->value, functionEndAddress), fData));
            }
        }
        return newSectionBuilder.setDataAndBuild();
    }

    section *getOriginalSection() const {
        return originalSectionData.s;
    };
};

class ConvertedFileBuilder {
    elfio writer;
    Elf_Word maxIndex = 0;

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

    void addSymbol(std::map<Elf_Word, Elf_Word> &tableIndexMappng, const Symbol &s, symbol_section_accessor &syma, string_section_accessor &stra) {
        Elf_Word newIndex = syma.add_symbol(stra, s.name.c_str(), s.value, s.size, s.bind, s.type, s.other, s.sectionIndex);
        mDebug << "Adding symbol: [" << newIndex << "] " << s << std::endl;
        tableIndexMappng[s.tableIndex] = newIndex;

        if (s.bind == STB_LOCAL) {
            maxIndex = std::max(maxIndex, newIndex + 1);
        }
    }

    void buildElfFile(const std::vector<SectionData> &sectionDatas, const std::vector<Symbol> &globalSymbols, const section *originalSymbolSection) {
        // Create string table section
        section *str_sec = writer.sections.add(".strtab");
        str_sec->set_type(SHT_STRTAB);
        std::map<Elf_Word, Elf_Word> tableIndexMapping;

        section *sym_sec = writer.sections.add(".symtab");
        sym_sec->set_type(SHT_SYMTAB);
        sym_sec->set_addr_align(originalSymbolSection->get_addr_align());
        sym_sec->set_entry_size(writer.get_default_entry_size(SHT_SYMTAB));
        sym_sec->set_link(str_sec->get_index());

        // Create string table writer
        string_section_accessor stra(str_sec);
        // Create symbol table writer
        symbol_section_accessor syma(writer, sym_sec);

        // Add global symbols
        for (const auto &s: globalSymbols) {
            addSymbol(tableIndexMapping, s, syma, stra);
        }
        for (const auto &s: sectionDatas) {
            mDebug << "Adding symbols declared in section " << s.s->get_name() << std::endl;
            if (s.sectionSymbol.has_value()) {
                addSymbol(tableIndexMapping, s.sectionSymbol.value(), syma, stra);
            }
            for (const auto &s_it: s.symbolsWithLocations) {
                addSymbol(tableIndexMapping, s_it, syma, stra);
            }
        }

        for (const auto &s: sectionDatas) {
            if (s.relatedRelocationsection.has_value()) {
                mDebug << "Section " << s.s->get_name() << " has relocations! Will be adding those relocations to the file" << std::endl;
                section *newRelocationSection = writer.sections.add(s.relatedRelocationsection.value()->get_name());

                newRelocationSection->set_type(s.relatedRelocationsection.value()->get_type());
                newRelocationSection->set_addr_align(s.relatedRelocationsection.value()->get_addr_align());
                newRelocationSection->set_entry_size(writer.get_default_entry_size(SHT_RELA));
                newRelocationSection->set_link(sym_sec->get_index());
                newRelocationSection->set_info(s.s->get_index());
                // Create relocation table writer
                relocation_section_accessor rela(writer, newRelocationSection);

                for (auto &r: s.relocations) {
                    rela.add_entry(r.offset, tableIndexMapping[r.symbol], r.type, r.addend);
                }
            }
        }

        sym_sec->set_info(maxIndex);
    }

    void save(const std::string &name) {
        writer.save(name);
    }
};

class ConvertManager {
    elfio fileToConvert;
    // Indexes in original section header;
    std::map<Elf_Half, SectionManager> sectionManagers;

    // File symbol and external symbols
    std::vector<Symbol> globalSymbols;
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

    static std::string
    getSectionNameFromRelocationSectionName(const std::string &relocationName) {
        assert(relocationName.substr(0, 5) == ".rela");
        return relocationName.substr(5);
    }

    void addSymbolsToSectionManager() {
        if (!symbolSectionIndex.has_value()) {
            zerror("Symbol section wan't parsed yet!");
        }
        const symbol_section_accessor symbols(fileToConvert, sectionManagers.find(symbolSectionIndex.value())->second.getOriginalSection());

        mDebug << "Parsing symbol section" << std::endl;
        for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {
            Symbol s;
            s.tableIndex = j;
            if (!symbols.get_symbol(j, s.name, s.value, s.size, s.bind, s.type,
                                    s.sectionIndex, s.other)) {
                zerror("Error getting symbol entry");
            }
            mDebug << s << std::endl;
            if (s.isGlobal()) {
                mWarn << "symbol is global, will not do anything" << std::endl;
                globalSymbols.push_back(s);
            } else if (Symbol::isSpecialUnhandled(s.sectionIndex)) {
                mWarn << "symbols from section " << s.sectionIndex << "are not handled "
                      << std::endl;
            } else {
                auto it = sectionManagers.find(s.sectionIndex);
                if (it != sectionManagers.end()) {
                    it->second.addSymbol(s);
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
        auto index = identifySectionByName(
                getSectionNameFromRelocationSectionName(relocationSection->get_name()));
        if (index < 0) {
            mWarn << "couldn't find section that the relocation section "
                  << relocationSection->get_name() << " relate to" << std::endl;
            return;
        }

        const relocation_section_accessor relocationSectionAccessor(
                fileToConvert, relocationSection);
        std::vector<Relocation> relocations;
        for (int i = 0; i < relocationSectionAccessor.get_entries_num(); i++) {
            Relocation r;
            if (!relocationSectionAccessor.get_entry(i, r.offset, r.symbol, r.type,
                                                     r.addend)) {
                zerror("Error getting relocation entry");
            }
            if (!Relocation::isRelocationHandled(r.type)) {
                mDebug << "relocation of this type is not handled" << std::endl;
            }
            relocations.push_back(r);
        }
        assert(sectionManagers.find(index) != sectionManagers.end());
        sectionManagers.find(index)->second.setRelocations(relocations, relocationSection);
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

            // https://stackoverflow.com/questions/3269590/can-elf-file-contain-more-than-one-symbol-table
            // There can be only one SYMTAB table
            if (psec->get_type() == SHT_SYMTAB) {
                symbolSectionIndex = i;
            } else if (psec->get_type() == SHT_RELA) {
                relocationSectionsToParse.push_back(i);
            }
            if (!isSkippable(psec->get_name())) {
                // pomyśleć co z symbolami, które odnoszą się do usuniętych sekcji
                sectionManagers.insert({i, SectionManager(psec)});
            }
        }
        addSymbolsToSectionManager();
        for (auto r: relocationSectionsToParse) {
            addRelocationsToRelocationManager(r);
        }
        mDebug << "Section parsing ended" << std::endl;
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
    }
    void convert(const std::string &outputFile) {
        ConvertedFileBuilder builder;
        std::vector<SectionData> convertedSections;
        // todo jeśli na qemu będą dodawane symbole każdej sekcji (w tym sekcji relokacji oraz symboli)
        // to będzie trzeba te symbole rówbnież przekaząźć builderowi
        for (auto &it: sectionManagers) {
            mDebug << it.first << ": ";
            if (it.second.getOriginalSection()->get_type() == SHT_SYMTAB) {
                mDebug << "not converting symtab section " << std::endl;
            } else if (it.second.getOriginalSection()->get_type() == SHT_RELA) {
                mDebug << "not converting relocation section " << it.second.getName() << std::endl;
            } else {
                mDebug << "converting section " << std::endl;
                convertedSections.push_back(it.second.convert(builder.getWriter()));
            }
        }
        builder.buildElfFile(convertedSections, globalSymbols, sectionManagers.find(symbolSectionIndex.value())->second.getOriginalSection());
        builder.save(outputFile);
    }
};

#endif// CONVERTERPROJECT_CONVERTMANAGER_H
