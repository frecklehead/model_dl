#!/usr/bin/env python3
"""
server_login.py
Run this on the SERVER host (h2).
Simulates a real banking login portal.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import time
import datetime
import os
import sys

# Ensure logs are visible immediately
sys.stdout.reconfigure(line_buffering=True)

SERVER_PORT = 8080
LOG_FILE = "/tmp/server_log.txt"

def log_event(msg):
    ts = datetime.datetime.now().strftime('%H:%M:%S')
    log_line = f"[{ts}] {msg}"
    print(log_line)
    with open(LOG_FILE, 'a') as f:
        f.write(log_line + "\n")

class BankHandler(BaseHTTPRequestHandler):
    def _send_html(self, content):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))

    def do_GET(self):
        client_ip = self.client_address[0]
        
        if self.path == '/':
            log_event(f"[HTTP] GET / from {client_ip}")
            html = """
            <html>
            <head><title>SecureBank Login</title></head>
            <body>
                <h1>Welcome to SecureBank</h1>
                <form method='POST' action='/login'>
                    Username: <input name='username'><br>
                    Password: <input name='password' type='password'><br>
                    <input type='submit' value='Login'>
                </form>
            </body>
            </html>
            """
            self._send_html(html)
            
        elif self.path == '/dashboard':
            log_event(f"[HTTP] GET /dashboard from {client_ip}")
            html = "<html><body><h1>Your Account Dashboard</h1><p>Balance: $10,000</p></body></html>"
            self._send_html(html)
            
        else:
            self.send_error(404)

    def do_POST(self):
        client_ip = self.client_address[0]
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(body)

        if self.path == '/login':
            user = params.get('username', ['?'])[0]
            pwd = params.get('password', ['?'])[0]
            log_event(f"[LOGIN] user={user} pass={pwd} | from={client_ip}")
            self._send_html("<html><body><h1>Login Successful!</h1><a href='/dashboard'>Go to Dashboard</a></body></html>")
            
        elif self.path == '/transfer':
            amount = params.get('amount', ['0'])[0]
            to_account = params.get('to', ['?'])[0]
            log_event(f"[TRANSFER] ${amount} to {to_account} | from={client_ip}")
            self._send_html("<html><body><h1>Transfer Complete!</h1></body></html>")
            
        else:
            self.send_error(404)
            
    def log_message(self, fmt, *args):
        # Suppress default logging to keep terminal clean
        pass

class BankServer(HTTPServer):
    allow_reuse_address = True

if __name__ == '__main__':
    # Clean previous log
    if os.path.exists(LOG_FILE):
        try:
            os.remove(LOG_FILE)
        except OSError:
            pass
        
    log_event("Attempting to start server...")
    
    try:
        server = BankServer(('0.0.0.0', SERVER_PORT), BankHandler)
        print(f"Server started on port {SERVER_PORT}...")
        log_event("Server started successfully.")
        server.serve_forever()
    except OSError as e:
        if e.errno == 98:
            print(f"❌ ERROR: Port {SERVER_PORT} is already in use.")
            print("Try killing the existing process with: fuser -k 8080/tcp")
            log_event(f"Error: Port {SERVER_PORT} in use.")
        else:
            print(f"❌ ERROR: {e}")
            log_event(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nServer stopping...")
        if 'server' in locals():
            server.server_close()
