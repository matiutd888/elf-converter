//
// Created by mateusz on 26.03.23.
//

#ifndef CONVERTERPROJECT_ELF_STRUCTURES_H
#define CONVERTERPROJECT_ELF_STRUCTURES_H


#include <elfio/elfio.hpp>
#include <optional>
#include <string>

using namespace ELFIO;

namespace ElfStructures {

    struct Symbol {
    private:
        static constexpr Elf_Word specialUnhandledSections[1] = {SHN_COMMON};

    public:
        size_t tableIndex;
        std::string name;
        // Address in section
        //    In relocatable files, st_value holds alignment constraints for a symbol
        //    whose section index is SHN_COMMON. In relocatable files, st_value holds
        //    a section offset for a defined symbol. That is, st_value is an offset
        //    from the beginning of the section that st_shndx identifies.
        Elf64_Addr value;
        Elf_Xword size;
        unsigned char bind;
        unsigned char type;
        unsigned char other;
        Elf_Half sectionIndex;

        static bool isExternal(Elf_Half sectionIndex) {
            return sectionIndex == SHN_UNDEF;
        }

        bool isSection() const {
            return type == STT_SECTION;
        }

        bool isSymbolWithLocation() const {
            return type == STT_NOTYPE || type == STT_FUNC || type == STT_OBJECT;
        }

        bool isGlobal() const {
            return (type == STT_FILE) || isExternal(sectionIndex);
        }

        static bool isSpecialUnhandled(Elf_Half sectionIndex) {
            return std::ranges::any_of(
                    specialUnhandledSections,
                    [sectionIndex](Elf_Word x) -> bool { return x == sectionIndex; });
        }

        bool isFunction() const { return type == STT_FUNC; }

        friend std::ostream &operator<<(std::ostream &os, const Symbol &symbol) {
            os << "name: " << symbol.name << " value: " << symbol.value
               << " size: " << symbol.size << " bind: " << symbol.bind
               << " type: " << symbol.type << " other: " << symbol.other;
            return os;
        }
    };

    class Relocation {
    public:
        Elf64_Addr offset;
        Elf_Word symbol;
        unsigned type;
        Elf_Sxword addend;

        Relocation() = default;

        Relocation(Elf64_Addr offset, Elf_Word symbol, unsigned type,
                   Elf_Sxword addend)
            : offset(offset), symbol(symbol), type(type), addend(addend) {}

        static bool isRelocationHandled(unsigned type) {
            return type == R_X86_64_PC32 | type == R_X86_64_PLT32 |
                   type == R_X86_64_32 | type == R_X86_64_32S | type == R_X86_64_64;
        }

        friend std::ostream &operator<<(std::ostream &os,
                                        const Relocation &relocation) {
            os << "offset: " << relocation.offset << " symbol: " << relocation.symbol
               << " type: " << relocation.type << " addend: " << relocation.addend;
            return os;
        }
    };


    struct SectionData {
        section *s;
        std::vector<Symbol> symbolsWithLocations;
        std::optional<Symbol> sectionSymbol;
        std::vector<Relocation> relocations;
        std::optional<section *> relatedRelocationsection;
    };
}


#endif//CONVERTERPROJECT_ELF_STRUCTURES_H
