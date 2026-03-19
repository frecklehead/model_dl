Root Cause Analysis
   1. Wrong Target IP: The error message HTTPConnectionPool(host='10.0.0.1', port=8080) confirms that the victim_traffic.py script is trying to reach 10.0.0.1. Since there is no web server running on the
      victim host, the connection is immediately refused.
   2. Attacker Traffic: The server showing /get from 10.0.0.100 is expected behavior. The attacker_mitm.py script contains a "bulk traffic generator" that sends continuous requests from the attacker's IP
      (10.0.0.100) to the server to ensure there is enough data for the Machine Learning model to analyze.


  How to Fix
  You need to ensure the victim script is pointing to the correct server IP (10.0.0.2) and that the server is actually running.

   1. Stop any existing victim traffic:
      In the Mininet CLI, stop any background processes:


   1     mininet> victim pkill -f victim_traffic.py

   2. Ensure the Server is running on the correct host:
   1     mininet> server python3 /tmp/server_login.py &


   3. Run the Victim script with the correct Server IP:
   1     mininet> victim python3 /tmp/victim_traffic.py 10.0.0.2


   4. If you still see errors:
      If the attack has already been detected and blocked by the Ryu controller, the victim's traffic will be dropped if the ARP table is still poisoned. You must clear the poisoned ARP entry on the
  victim:
   1     mininet> victim arp -d 10.0.0.2


  Summary of IP Roles
   * 10.0.0.1: Victim (Should run victim_traffic.py 10.0.0.2)
   * 10.0.0.2: Server (Should run server_login.py)
   * 10.0.0.100: Attacker (Runs attacker_mitm.py)

   