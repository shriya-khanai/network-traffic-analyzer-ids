
from collections import defaultdict
from datetime import datetime, timedelta


# ========================================
# PORT SCAN DETECTION - SAFE TEST
# ========================================

PORT_SCAN_THRESHOLD = 10
TIME_WINDOW_SECONDS = 10

connections = defaultdict(list)


def detect_port_scan(source_ip, destination_ip, destination_port, timestamp):
    key = (source_ip, destination_ip)

    # Record this connection attempt
    connections[key].append((timestamp, destination_port))

    # Keep only events within the time window
    cutoff = timestamp - timedelta(seconds=TIME_WINDOW_SECONDS)

    connections[key] = [
        (event_time, port)
        for event_time, port in connections[key]
        if event_time >= cutoff
    ]

    # Count unique destination ports in this window
    unique_ports = {
        port for event_time, port in connections[key]
    }

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:
        print("\n" + "=" * 50)
        print("         POSSIBLE PORT SCAN DETECTED!")
        print("=" * 50)
        print("Source IP       :", source_ip)
        print("Destination IP  :", destination_ip)
        print("Unique Ports    :", len(unique_ports))
        print("Ports Observed  :", sorted(unique_ports))
        print("Time Window     :", TIME_WINDOW_SECONDS, "seconds")
        print("Note            : This is a simulated test alert.")
        print("=" * 50)

        # Clear this window so the same test does not
        # alert repeatedly for every additional port.
        connections[key].clear()


# ========================================
# SIMULATED TEST DATA
# ========================================

print("=" * 50)
print("       PORT SCAN DETECTION TEST")
print("=" * 50)

source_ip = "192.168.1.100"
destination_ip = "192.168.1.10"

start_time = datetime.now()

print("\nSimulating connections to different ports...")
print("No real network scan will be performed.\n")

for port in range(20, 32):
    simulated_time = start_time + timedelta(seconds=port - 20)

    print(
        "Simulated connection:",
        source_ip,
        "->",
        destination_ip,
        "Port:",
        port
    )

    detect_port_scan(
        source_ip,
        destination_ip,
        port,
        simulated_time
    )

print("\nTest completed.")
