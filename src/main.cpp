#include <iostream>
#include <elfio/elfio.hpp>
#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include "ConvertManager.h"

using namespace ELFIO;

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cout << "Usage: tutorial <elf_file>" << std::endl;
        return 1;
    }
//    elfio reader;

//    if (!reader.load(argv[1])) {
//        std::cout << "Can't find or process ELF file " << argv[1] << std::endl;
//    }
//
//    std::cout << reader.get_elf_version() << std::endl;

    ConvertManager manager(argv[1]);
}