//
// Created by mateusz on 11.03.23.
//

#include <capstone/capstone.h>
#include <iostream>

#ifndef LA1_UTILS_H
#define LA1_UTILS_H

#endif//LA1_UTILS_H

using word_t = char;

#define zerror(I, ...)                 \
    fprintf(stderr, I, ##__VA_ARGS__); \
    exit(1)

#include <keystone/keystone.h>
#include <memory>
#include <stdexcept>
#include <string>

//https://stackoverflow.com/questions/2342162/stdstring-formatting-like-sprintf
template<typename... Args>
std::string string_format(const std::string &format, Args... args) {
    int size_s = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;// Extra space for '\0'
    if (size_s <= 0) { throw std::runtime_error("Error during formatting."); }
    auto size = static_cast<size_t>(size_s);
    std::unique_ptr<char[]> buf(new char[size]);
    std::snprintf(buf.get(), size, format.c_str(), args...);
    return std::string(buf.get(), buf.get() + size - 1);// We don't want the '\0' inside
}

class CapstoneUtils {
    csh handle;
    uint64_t DEFAULT_START_ADDRESS = 0;


    explicit CapstoneUtils(cs_mode mode = CS_MODE_64) {
        if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
            std::cerr << "Error creating cs handle" << std::endl;
            exit(1);
        }
        if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON)) {
            zerror("Error turining on cs opt detail");
        }// turn ON detail feature with CS_OPT_ON
    }


public:
    static CapstoneUtils &getInstance() {
        static CapstoneUtils instance;// Guaranteed to be destroyed.
                                      // Instantiated on first use.
        return instance;
    }

    std::string getRegName(x86_reg reg) const {
        return cs_reg_name(handle, reg);
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

    CapstoneUtils(CapstoneUtils const &) = delete;
    void operator=(CapstoneUtils const &) = delete;
};


class KeystoneUtils {
    ks_engine *ks;

    KeystoneUtils() {
        ks_err err = ks_open(KS_ARCH_ARM64, KS_MODE_64, &ks);
        if (err != KS_ERR_OK) {
            zerror("ERROR: failed on ks_open(), quit\n");
        }
    }
public:
    static KeystoneUtils &getInstance() {
        static KeystoneUtils k;
        return k;
    }

    void assemble(const char *code, unsigned char **encode,
                  size_t &size, size_t &count) {
        if (ks_asm(ks, code, 0, encode, &size, &count) != KS_ERR_OK) {
            zerror("ERROR: ks_asm() failed & count = %lu, error = %u\n", count, ks_errno(ks));
        }
    }

    ~KeystoneUtils() {
        // close Keystone instance when done
        ks_close(ks);
    }
};