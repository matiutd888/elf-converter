#include <iostream>
#include <elfio/elfio.hpp>
#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include "ConvertManager.h"

using namespace ELFIO;

int main(int argc, char **argv) {
    if (argc != 3) {
        std::cout << "Usage: converter <elf_file> <output-file>" << std::endl;
        return 1;
    }
    ConvertManager manager(argv[1]);
    manager.convert(argv[2]);
}