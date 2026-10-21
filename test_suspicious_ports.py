
# ========================================
# SUSPICIOUS PORT MONITORING TEST
# ========================================

# These ports are monitored for awareness.
# Their use does NOT automatically mean an attack.

MONITORED_PORTS = {
    23: "Telnet",
    22: "SSH",
    3389: "Remote Desktop (RDP)"
}


def check_suspicious_port(destination_port):
    """Return an alert message for a monitored port."""

    if destination_port in MONITORED_PORTS:
        service = MONITORED_PORTS[destination_port]

        return (
            f"Monitored port detected: "
            f"{destination_port} ({service})"
        )

    return None


# ========================================
# SIMULATED TESTS
# ========================================

print("=" * 55)
print("SUSPICIOUS PORT MONITORING TEST")
print("=" * 55)

# Test 1: A monitored port should trigger an alert.
print("\nTEST 1: Monitored port 23")

alert = check_suspicious_port(23)

print("Alert:", alert)
test1_passed = alert is not None
print("Test result:", "PASSED" if test1_passed else "FAILED")


# Test 2: An ordinary unmonitored port should not alert.
print("\nTEST 2: Unmonitored port 8080")

alert = check_suspicious_port(8080)

print("Alert:", alert)
test2_passed = alert is None
print("Expected: No alert")
print("Test result:", "PASSED" if test2_passed else "FAILED")


# Test 3: Check RDP port.
print("\nTEST 3: Monitored port 3389")

alert = check_suspicious_port(3389)

print("Alert:", alert)
test3_passed = alert is not None
print("Test result:", "PASSED" if test3_passed else "FAILED")


# ========================================
# FINAL RESULTS
# ========================================

print("\n" + "=" * 55)

if test1_passed and test2_passed and test3_passed:
    print("RESULT: ALL 3 SUSPICIOUS PORT TESTS PASSED!")
else:
    print("RESULT: ONE OR MORE TESTS FAILED")

print("=" * 55)
print("All test data is simulated.")
print("No real network traffic was generated.")
