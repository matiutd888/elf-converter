//
// Created by mateusz on 11.03.23.
//

#include "Utils.h"
#include <keystone/keystone.h>

KeystoneUtils::~KeystoneUtils() {
    // close Keystone instance when done
    ks_close(ks);
}
KeystoneUtils &KeystoneUtils::getInstance() {
    static KeystoneUtils k;
    return k;
}
void KeystoneUtils::assemble(const char *code, unsigned char **encode, size_t &size, size_t &count) {
    if (ks_asm(ks, code, 0, encode, &size, &count) != KS_ERR_OK) {
        zerror("ERROR: ks_asm() failed & count = %lu, error = %u\n", count, ks_errno(ks));
    }
}
