#ifndef CLIPBOARD_H
#define CLIPBOARD_H

#include <windows.h>
#include <stddef.h>

/**
 * Module Clipboard - Capture du contenu du presse-papier
 *
 * Gère trois formats :
 *   CF_UNICODETEXT → texte (converti UTF-8)
 *   CF_HDROP       → liste de fichiers copiés
 *   CF_BITMAP/DIB  → image détectée (non capturée)
 */

#define CLIPBOARD_SUCCESS       0
#define CLIPBOARD_ERROR_OPEN    1
#define CLIPBOARD_ERROR_EMPTY   2

/**
 * Lit le contenu actuel du presse-papier
 *
 * @param output  Buffer de sortie
 * @param size    Taille du buffer
 * @return CLIPBOARD_SUCCESS ou code d'erreur
 */
int clipboard_get(char *output, size_t size);

#endif // CLIPBOARD_H
