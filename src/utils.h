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

#include <memory>
#include <string>
#include <stdexcept>

//https://stackoverflow.com/questions/2342162/stdstring-formatting-like-sprintf
template<typename ... Args>
std::string string_format(const std::string &format, Args ... args) {
    int size_s = std::snprintf(nullptr, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
    if (size_s <= 0) { throw std::runtime_error("Error during formatting."); }
    auto size = static_cast<size_t>( size_s );
    std::unique_ptr<char[]> buf(new char[size]);
    std::snprintf(buf.get(), size, format.c_str(), args ...);
    return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
}

class CapstoneUtils {
    csh handle;
    uint64_t DEFAULT_START_ADDRESS = 0;
public:
    explicit CapstoneUtils(cs_mode mode = CS_MODE_64) {
        if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
            std::cerr << "Error creating cs handle" << std::endl;
            exit(1);
        }
        if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON)) {
            zerror("Error turining on cs opt detail");
        } // turn ON detail feature with CS_OPT_ON
    }

    size_t disassemble(const uint8_t *code, size_t code_size, cs_insn **insn) const {
        size_t count = cs_disasm(handle, code, code_size, DEFAULT_START_ADDRESS, 0, insn);
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
