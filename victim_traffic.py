import requests
import time
import random
import datetime

SERVER_URL = "http://10.0.0.2:8080"
USERS = [
    ("alice", "secret123"),
    ("bob", "pass456"),
    ("carol", "mypassword")
]

def simulate_session():
    user, password = random.choice(USERS)
    ts = datetime.datetime.now().strftime('%H:%M:%S')
    print(f"[{ts}] Victim browsing as {user}...")
    
    session = requests.Session()
    
    # 1. Browse Homepage
    try:
        r = session.get(SERVER_URL + "/")
        print(f"[{ts}] GET / (homepage) - Status: {r.status_code}")
        time.sleep(random.uniform(1, 2))
        
        # 2. Login
        r = session.post(SERVER_URL + "/login", data={"user": user, "pass": password})
        print(f"[{ts}] POST /login user={user} pass={password} - Status: {r.status_code}")
        time.sleep(random.uniform(1, 2))
        
        # 3. View Dashboard
        r = session.get(SERVER_URL + "/dashboard")
        print(f"[{ts}] Viewing dashboard...")
        time.sleep(random.uniform(1, 2))
        
        # 4. Transfer Money
        amount = random.randint(10, 500)
        to_acc = "bank-user-" + str(random.randint(100, 999))
        r = session.post(SERVER_URL + "/transfer", data={"amount": amount, "account": to_acc})
        print(f"[{ts}] POST /transfer amount=${amount} to={to_acc}")
        time.sleep(random.uniform(1, 2))
        
    except requests.exceptions.RequestException as e:
        print(f"[{ts}] Network Error: {e}")

if __name__ == '__main__':
    print("Victim traffic simulation started...")
    while True:
        simulate_session()
        delay = random.uniform(3, 5)
        time.sleep(delay)
