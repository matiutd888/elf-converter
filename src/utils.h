//
// Created by mateusz on 11.03.23.
//

#include <capstone/capstone.h>
#include <iostream>

#ifndef LA1_UTILS_H
#define LA1_UTILS_H

#endif //LA1_UTILS_H

using word_t = char;

class CapstoneUtils {
    csh handle;
    uint64_t DEFAULT_START_ADDRESS = 0;
public:
    CapstoneUtils(cs_mode mode = CS_MODE_64) {
        if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
            std::cerr << "Error creating cs handle" << std::endl;
            exit(1);
        }
    }

    size_t disassemble(const uint8_t *code, size_t code_size, cs_insn *insn) {
        size_t count = cs_disasm(handle, code, code_size, DEFAULT_START_ADDRESS, 0, &insn);
        if (count > 0) {
            return count;
        } else {
            std::cerr << "No instruction were disassembled" << std::endl;
            exit(1);
        }
    }

    ~CapstoneUtils() {
        cs_close(&handle);
    }
};

void perror(const char *errorMessage) {
    std::cerr << errorMessage << std::endl;
    exit(1);
}