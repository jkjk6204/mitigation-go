import socket
import threading
import time

# Constants for DDoS detection
TCP_THRESHOLD = 200
UDP_THRESHOLD = 100
HTTPS_THRESHOLD = 50
SMTP_THRESHOLD = 30
FTP_THRESHOLD = 20
TELNET_THRESHOLD = 10
POP3_THRESHOLD = 15
IMAP_THRESHOLD = 15
ICMP_THRESHOLD = 30
SSH_THRESHOLD = 10
GOPHER_THRESHOLD = 5
DETECTION_INTERVAL = 60
BLOCK_DURATION = 600

# Dictionaries to store traffic counts for each protocol
traffic_counts = {
    "tcp": {},
    "udp": {},
    "https": {},
    "smtp": {},
    "ftp": {},
    "telnet": {},
    "pop3": {},
    "imap": {},
    "icmp": {},
    "ssh": {},
    "gopher": {},
}

# Function to block incoming traffic from a specific IP address
def block_ip(ip_address, protocol):
    # Implement IP blocking based on the protocol
    print(f"Blocked incoming {protocol} traffic from {ip_address}")

# Function to detect and mitigate DDoS attacks for a specific protocol
def detect_and_mitigate_ddos(protocol):
    while True:
        current_time = int(time.time())

        for ip, count in list(traffic_counts[protocol].items()):
            # If traffic count exceeds the threshold, block the IP
            if count > THRESHOLDS[protocol]:
                block_ip(ip, protocol)
                traffic_counts[protocol].pop(ip, None)
                print(f"DDoS detected from {ip} on protocol {protocol}. Blocked.")
            else:
                traffic_counts[protocol][ip] = 0

        time.sleep(DETECTION_INTERVAL)

# Function to handle incoming connections
def handle_connection(connection, protocol):
    remote_ip, _ = connection.getpeername()
    traffic_counts[protocol][remote_ip] = traffic_counts[protocol].get(remote_ip, 0) + 1
    # Handle the connection here (e.g., for logging or further processing)
    connection.close()

# Start DDoS detection threads for each protocol
for protocol in traffic_counts.keys():
    ddos_detection_thread = threading.Thread(target=detect_and_mitigate_ddos, args=(protocol,))
    ddos_detection_thread.daemon = True
    ddos_detection_thread.start()

# Start listening on ports for various protocols
def listen_on_port(port, protocol):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server_socket.bind(("0.0.0.0", port))
        server_socket.listen(5)
        print(f"Listening on port {port} for {protocol} traffic...")
        
        while True:
            client_socket, addr = server_socket.accept()
            connection_thread = threading.Thread(target=handle_connection, args=(client_socket, protocol))
            connection_thread.start()
    
    except Exception as e:
        print(f"Error on port {port} ({protocol}): {e}")

# Define the ports and protocols to monitor
ports_and_protocols = [
    (8080, "tcp"),
    (8081, "tcp"),
    (8443, "https"),
    # Add more ports and protocols as needed
]

# Start listening on specified ports for various protocols
for port, protocol in ports_and_protocols:
    listen_thread = threading.Thread(target=listen_on_port, args=(port, protocol))
    listen_thread.daemon = True
    listen_thread.start()

while True:
    pass  # Keep the main thread running
