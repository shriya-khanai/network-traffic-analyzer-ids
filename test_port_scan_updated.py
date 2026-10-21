
import csv
from io import StringIO
from datetime import datetime, timedelta

from scapy.all import IP, TCP

import packet_capture as analyzer


# ========================================
# CONNECT TEST TO THE REAL DETECTOR
# ========================================

# Keep test alerts in memory. Do not overwrite project CSV files.
test_alert_output = StringIO()
analyzer.alert_file = test_alert_output
analyzer.alert_writer = csv.writer(test_alert_output)

# Reset detection state for repeatable tests.
analyzer.recent_ports.clear()
analyzer.last_alert_time.clear()
analyzer.port_scan_alerts = 0

for key in analyzer.stats:
    analyzer.stats[key] = 0


# ========================================
# TEST 1: SCAN-LIKE TCP PACKETS
# ========================================

print("=" * 55)
print("TEST 1: SIMULATED TCP SCAN-LIKE TRAFFIC")
print("=" * 55)

start_time = datetime.now()
tcp_alert_detected = False

for port in range(20, 30):

    packet = (
        IP(src="192.0.2.10", dst="192.0.2.20")
        / TCP(
            sport=40000 + port,
            dport=port,
            flags="S"
        )
    )

    # Use the actual packet analyzer from packet_capture.py.
    analyzer.analyze_packet(packet)

    if analyzer.port_scan_alerts > 0:
        tcp_alert_detected = True

print()
print("Scan-like traffic triggered an alert:", tcp_alert_detected)
print("Expected result: True")


# ========================================
# TEST 2: TCP RESPONSE PACKETS
# ========================================

print()
print("=" * 55)
print("TEST 2: SIMULATED HTTPS RESPONSE TRAFFIC")
print("=" * 55)

# Reset detector state for the second test.
analyzer.recent_ports.clear()
analyzer.last_alert_time.clear()
analyzer.port_scan_alerts = 0

response_start = datetime.now()
response_alert_detected = False

for index in range(10):

    packet = (
        IP(src="192.0.2.20", dst="192.0.2.10")
        / TCP(
            sport=443,
            dport=50000 + index,
            flags="A"
        )
    )

    analyzer.analyze_packet(packet)

    if analyzer.port_scan_alerts > 0:
        response_alert_detected = True

print()
print("Response traffic triggered an alert:", response_alert_detected)
print("Expected result: False")


# ========================================
# FINAL RESULTS
# ========================================

print()
print("=" * 55)

if tcp_alert_detected and not response_alert_detected:
    print("RESULT: BOTH INTEGRATED TESTS PASSED!")
else:
    print("RESULT: ONE OR MORE TESTS FAILED")

print("=" * 55)

print()
print("Note: All packets were simulated.")
print("No network scan was performed.")
