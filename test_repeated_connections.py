
from collections import Counter

# ========================================
# REPEATED CONNECTION DETECTION TEST
# ========================================

REPEAT_THRESHOLD = 5

def detect_repeated_connections(packets):
    """
    Detect repeated connections between the same
    source IP, destination IP and destination port.
    """
    counts = Counter()
    alerts = []

    for packet in packets:
        key = (
            packet["source_ip"],
            packet["destination_ip"],
            packet["destination_port"]
        )

        counts[key] += 1

        if counts[key] == REPEAT_THRESHOLD:
            alerts.append(
                f"Possible repeated connections: "
                f"{key[0]} -> {key[1]}:{key[2]} "
                f"({counts[key]} observations)"
            )

    return alerts


# ========================================
# SIMULATED TEST DATA
# ========================================

print("=" * 55)
print("REPEATED CONNECTION DETECTION TEST")
print("=" * 55)

normal_packets = [
    {"source_ip": "192.168.1.10", "destination_ip": "192.168.1.20", "destination_port": 80},
    {"source_ip": "192.168.1.10", "destination_ip": "192.168.1.30", "destination_port": 443},
    {"source_ip": "192.168.1.10", "destination_ip": "192.168.1.20", "destination_port": 80},
]

alerts = detect_repeated_connections(normal_packets)

print("\nTEST 1: Normal traffic")
print("Alerts detected:", len(alerts))
print("Expected alerts: 0")
normal_passed = len(alerts) == 0
print("Test result:", "PASSED" if normal_passed else "FAILED")


repeated_packets = [
    {"source_ip": "192.168.1.10", "destination_ip": "192.168.1.20", "destination_port": 22}
    for _ in range(6)
]

alerts = detect_repeated_connections(repeated_packets)

print("\nTEST 2: Repeated connection traffic")
print("Alerts detected:", len(alerts))

for alert in alerts:
    print("ALERT:", alert)

repeat_passed = len(alerts) == 1
print("Expected alerts: 1")
print("Test result:", "PASSED" if repeat_passed else "FAILED")


print("\n" + "=" * 55)

if normal_passed and repeat_passed:
    print("RESULT: BOTH REPEATED CONNECTION TESTS PASSED!")
else:
    print("RESULT: ONE OR MORE TESTS FAILED")

print("=" * 55)
print("All packets in this test are simulated.")
print("No real network traffic was generated.")
