
#include "ConvertManager.h"


void ConvertedFileBuilder::buildElfFile(const std::vector<ElfStructures::SectionData> &sectionDatas,
                                        const std::vector<ElfStructures::Symbol> &externalSymbols,
                                        const section *originalSymbolSection) {
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

    std::vector<ElfStructures::Symbol> symbolsToAdd;
    std::vector<ElfStructures::Symbol> sectionSymbolsToAdd;
    // Add global symbols
    mDebug << "start add external symbols" << std::endl;
    for (const auto &s : externalSymbols) {
        if (!s.isZeroEntry()) {
            symbolsToAdd.push_back(s);
        }
    }

    for (const auto &s: sectionDatas) {
        mDebug << "Adding symbols declared in section " << s.s->get_index() << " " << s.s->get_name() << std::endl;
        if (s.sectionSymbol.has_value()) {
            sectionSymbolsToAdd.push_back(s.sectionSymbol.value());
        }
        for (const auto &s_it: s.symbolsWithLocations) {
            symbolsToAdd.push_back(s_it);
        }
    }

    // Add local symbols first
    for (const auto &s: symbolsToAdd) {
        if (s.bind == STB_LOCAL) {
            addSymbol(tableIndexMapping, s, syma, stra);
        }
    }
    for (const auto &s: sectionSymbolsToAdd) {
        if (s.bind == STB_LOCAL) {
            addSectionSymbol(tableIndexMapping, s, syma);
        }
    }

    // And non-local symbols second
    for (const auto &s: symbolsToAdd) {
        if (s.bind != STB_LOCAL) {
            addSymbol(tableIndexMapping, s, syma, stra);
        }
    }
    for (const auto &s: sectionSymbolsToAdd) {
        if (s.bind != STB_LOCAL) {
            addSectionSymbol(tableIndexMapping, s, syma);
        }
    }

    for (const auto &s: sectionDatas) {
        if (s.relatedRelocationsection.has_value()) {
            mDebug << "Section " << s.s->get_name() << " has relocations! Will be adding those relocations to the file"
                   << std::endl;
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

    sym_sec->set_info(maxLocalIndex);
}

ElfStructures::SectionData SectionManager::convert(elfio &writer) {
    section *newSection = writer.sections.add(originalSectionData.s->get_name());
    SectionBuilder newSectionBuilder(newSection, originalSectionData.relatedRelocationsection);
    newSectionBuilder.copyMetaData(originalSectionData.s);

    if (originalSectionData.sectionSymbol.has_value()) {
        newSectionBuilder.setSectionSymbol(originalSectionData.sectionSymbol.value());
    }

    std::sort(originalSectionData.symbolsWithLocations.begin(),
              originalSectionData.symbolsWithLocations.end(),
              [](const ElfStructures::Symbol &s1, const ElfStructures::Symbol &s2) -> bool {
                  return s1.value < s2.value;
              });
    std::sort(originalSectionData.relocations.begin(),
              originalSectionData.relocations.end(),
              [](ElfStructures::Relocation r1, ElfStructures::Relocation r2) -> bool {
                  return r1.offset < r2.offset;
              });
    auto symbolsIt = originalSectionData.symbolsWithLocations.cbegin();


    size_t chunkStart = 0;
    bool end = false;
    while (!end) {
        std::vector<ElfStructures::Symbol> chunkSymbols;
        size_t chunkEnd;
        std::optional<ElfStructures::Symbol> function;
        while (symbolsIt != originalSectionData.symbolsWithLocations.end() && !symbolsIt->isFunction()) {
            chunkSymbols.push_back(*symbolsIt);
            symbolsIt++;
        }
        if (symbolsIt != originalSectionData.symbolsWithLocations.end()) {
            function = *symbolsIt;
            chunkEnd = symbolsIt->value;
            symbolsIt++;
        } else {
            end = true;
            chunkEnd = originalSectionData.s->get_size();
        }

        mDebug << "original section data size: " << originalSectionData.s->get_size() << std::endl;
        mDebug << "will try to read indexes (" << chunkStart << ", " << chunkEnd << ")" << std::endl;


        size_t chunkSize = chunkEnd - chunkStart;
        unsigned char const *chunkBytes;
        if (originalSectionData.s->get_type() == SHT_NOBITS) {
            chunkBytes = nullptr;
        } else {
            chunkBytes = reinterpret_cast<const unsigned char *>(&originalSectionData.s->get_data()[chunkStart]);
        }
        newSectionBuilder.addNonFunctionChunk(chunkSize,
                                              chunkStart,
                                              chunkBytes,
                                              chunkSymbols,
                                              getRelatedRelocations(originalSectionData.relocations, chunkStart,
                                                                    chunkEnd));

        if (function.has_value()) {
            address_t functionEndAddress = function->value + function->size;
            chunkStart = functionEndAddress;
            assert(originalSectionData.s->get_data() != nullptr);
            assert(originalSectionData.s->get_size() >= functionEndAddress);

            const FunctionData fData(&originalSectionData.s->get_data()[function->value], function->size,
                                     function->value);

            newSectionBuilder.addConvertedFunctionData(function.value(),
                                                       FunctionConverter::convert(getRelatedRelocations(
                                                                                          originalSectionData.relocations,
                                                                                          function->value,
                                                                                          functionEndAddress), fData));
        }
    }
    return newSectionBuilder.setDataAndBuild();
}

void SectionBuilder::addNonFunctionChunk(size_t size,
                                         address_t originalChunkAddress,
                                         const unsigned char *chunkBytes,
                                         const std::vector<ElfStructures::Symbol> &relatedSymbols,
                                         const std::vector<ElfStructures::Relocation> &relatedRelocations) {

    address_t newChunkAddress = sectionSize();
    Elf_Sxword diff = (Elf_Sxword) newChunkAddress - (Elf_Sxword) originalChunkAddress;
    for (const auto &s: relatedSymbols) {
        mDebug << "adding non function symbol " << s << std::endl;
        ElfStructures::Symbol newS = s;
        assert(newS.type == STT_NOTYPE || newS.type == STT_OBJECT);
        newS.value += diff;
        newS.sectionIndex = data.s->get_index();
        data.symbolsWithLocations.push_back(newS);
    }
    for (const auto &rel: relatedRelocations) {
        ElfStructures::Relocation newRel = rel;
        newRel.offset += diff;

        mDebug << rel << std::endl;
        assert(rel.type == R_X86_64_64);
        newRel.type = R_AARCH64_ABS64;
        data.relocations.push_back(newRel);
    }
    sSize += size;
    if (chunkBytes != nullptr) {
        for (size_t i = 0; i < size; i++) {
            bytes.push_back(chunkBytes[i]);
        }
    }
}

void SectionBuilder::addConvertedFunctionData(const ElfStructures::Symbol &originalSymbol,
                                              const ConvertedFunctionData &fData) {
    address_t functionAddress = sectionSize();
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
        mDebug << "keystoneSize: " << keystoneSize << std::endl;
        mDebug << "fSize: " << fSize << std::endl;
        assert(keystoneSize == fSize);

        sSize += keystoneSize;
        for (size_t i = 0; i < keystoneSize; i++) {
            bytes.push_back(encoded[i]);
        }
        free(encoded);
    }
    ElfStructures::Symbol newFSymbol = originalSymbol;
    newFSymbol.value = functionAddress;
    newFSymbol.size = fSize;
    newFSymbol.sectionIndex = data.s->get_index();
    data.symbolsWithLocations.push_back(newFSymbol);
}
