
from collections import deque
from datetime import datetime, timedelta


# ========================================
# TRAFFIC SPIKE DETECTION TEST
# ========================================

TRAFFIC_THRESHOLD = 100
TIME_WINDOW_SECONDS = 10


def detect_traffic_spike(packet_times):
    """
    Detect whether more than the configured number
    of packets arrive within the time window.
    """

    recent_packets = deque()
    alerts = []

    for packet_time in packet_times:

        recent_packets.append(packet_time)

        cutoff = packet_time - timedelta(
            seconds=TIME_WINDOW_SECONDS
        )

        while recent_packets and recent_packets[0] < cutoff:
            recent_packets.popleft()

        if len(recent_packets) > TRAFFIC_THRESHOLD:
            alerts.append({
                "time": packet_time,
                "packet_count": len(recent_packets)
            })

            # Stop after the first alert in this test.
            break

    return alerts


# ========================================
# TEST 1: NORMAL TRAFFIC
# ========================================

print("=" * 50)
print("TEST 1: NORMAL TRAFFIC")
print("=" * 50)

start_time = datetime(2026, 1, 1, 12, 0, 0)

normal_packet_times = [
    start_time + timedelta(seconds=i)
    for i in range(20)
]

normal_alerts = detect_traffic_spike(normal_packet_times)

print("Packets generated :", len(normal_packet_times))
print("Traffic spike alert:", bool(normal_alerts))
print("Expected result   : False")

normal_passed = not normal_alerts

print("Test result       :", "PASSED" if normal_passed else "FAILED")


# ========================================
# TEST 2: SIMULATED TRAFFIC SPIKE
# ========================================

print()
print("=" * 50)
print("TEST 2: SIMULATED TRAFFIC SPIKE")
print("=" * 50)

spike_packet_times = [
    start_time + timedelta(milliseconds=i * 50)
    for i in range(150)
]

spike_alerts = detect_traffic_spike(spike_packet_times)

print("Packets generated :", len(spike_packet_times))
print("Threshold         :", TRAFFIC_THRESHOLD)
print("Time window       :", TIME_WINDOW_SECONDS, "seconds")
print("Traffic spike alert:", bool(spike_alerts))
print("Expected result   : True")

if spike_alerts:
    print("Alert message     : Possible traffic spike detected!")
    print("Packets in window :", spike_alerts[0]["packet_count"])

spike_passed = bool(spike_alerts)

print("Test result       :", "PASSED" if spike_passed else "FAILED")


# ========================================
# FINAL TEST RESULTS
# ========================================

print()
print("=" * 50)

if normal_passed and spike_passed:
    print("RESULT: BOTH TRAFFIC SPIKE TESTS PASSED!")
else:
    print("RESULT: ONE OR MORE TESTS FAILED")

print("=" * 50)
print("All packets in this test are simulated.")
print("No real network traffic was generated.")
