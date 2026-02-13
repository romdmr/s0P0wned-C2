#ifndef WATCHDOG_H
#define WATCHDOG_H

#include <windows.h>

/**
 * Démarre le watchdog dans un thread séparé
 * Le watchdog surveille le processus principal et le redémarre s'il meurt
 */
HANDLE start_watchdog();

/**
 * Arrête le watchdog proprement
 */
void stop_watchdog(HANDLE watchdog_handle);

/**
 * Lance une instance de l'agent en tant que processus enfant
 * Utilisé par le watchdog pour redémarrer l'agent
 */
BOOL spawn_agent_process(const char *exe_path);

/**
 * Vérifie si un autre processus agent tourne déjà
 * Utilise un mutex global pour éviter les doublons
 */
BOOL check_already_running();

/**
 * Crée le mutex de protection contre les instances multiples
 */
HANDLE create_singleton_mutex();

#endif // WATCHDOG_H