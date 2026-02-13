#!/usr/bin/env python3
"""
Générateur de strings obfusquées pour C
Usage: python obfuscate_string.py "ma string"
"""

import sys

XOR_KEY = 0x42

def obfuscate(text):
    """Obfusque une string avec XOR"""
    obfuscated = [hex(ord(c) ^ XOR_KEY) for c in text]
    obfuscated.append('0x00')  # Null terminator
    return ', '.join(obfuscated)

def generate_c_array(name, text):
    """Génère un array C obfusqué"""
    obfuscated = obfuscate(text)
    return f'static const char {name}[] = {{\n    {obfuscated}\n}};'

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python obfuscate_string.py \"your string\"")
        print("\nExamples:")
        print('  python obfuscate_string.py "schtasks"')
        print('  python obfuscate_string.py "HKEY_CURRENT_USER"')
        sys.exit(1)

    text = sys.argv[1]
    var_name = "OBFS_STRING" if len(sys.argv) < 3 else sys.argv[2]

    print(f"\n// Original: \"{text}\"")
    print(generate_c_array(var_name, text))
    print()
