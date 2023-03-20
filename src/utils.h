//
// Created by mateusz on 11.03.23.
//

#include <capstone/capstone.h>
#include <iostream>

#ifndef LA1_UTILS_H
#define LA1_UTILS_H

#endif //LA1_UTILS_H

using word_t = char;


inline void zerror(const char *errorMessage) {
    std::cerr << errorMessage << std::endl;
    exit(1);
}

class CapstoneUtils {
    csh handle;
    uint64_t DEFAULT_START_ADDRESS = 0;
public:
    CapstoneUtils(cs_mode mode = CS_MODE_64) {
        if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
            std::cerr << "Error creating cs handle" << std::endl;
            exit(1);
        }
        if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON)) {
            zerror("Error turining on cs opt detail");
        } // turn ON detail feature with CS_OPT_ON
    }

    size_t disassemble(const uint8_t *code, size_t code_size, cs_insn *insn) {
        size_t count = cs_disasm(handle, code, code_size, DEFAULT_START_ADDRESS, 0, &insn);
        if (count > 0) {
            return count;
        } else {
            zerror("No instruction were disassembled");
        }
    }

    ~CapstoneUtils() {
        cs_close(&handle);
    }
};
