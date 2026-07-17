import sys
import os
import socket
import threading
import webview
from app import app

def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port

def start_flask(port):
    # Run the Flask app on localhost
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)

if __name__ == "__main__":
    port = get_free_port()
    
    # Start Flask server in a daemon thread
    # Daemon thread means it terminates automatically when the main GUI process exits.
    t = threading.Thread(target=start_flask, args=(port,), daemon=True)
    t.start()
    
    # Start webview window
    webview.create_window(
        "Office Stationery Manager", 
        f"http://127.0.0.1:{port}", 
        width=1280, 
        height=800,
        min_size=(900, 600)
    )
    webview.start()
