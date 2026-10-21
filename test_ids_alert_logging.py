
import csv
import os
import tempfile
from datetime import datetime


# ========================================
# IDS ALERT LOGGING TEST
# ========================================

def log_alert(
    writer,
    alert_type,
    source_ip,
    destination_ip,
    message
):
    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    writer.writerow([
        timestamp,
        alert_type,
        source_ip,
        destination_ip,
        message
    ])


print("=" * 55)
print("IDS ALERT LOGGING TEST")
print("=" * 55)

# Use a temporary file so your existing project
# CSV files are not overwritten.
with tempfile.NamedTemporaryFile(
    mode="w",
    newline="",
    encoding="utf-8",
    suffix=".csv",
    delete=False
) as temporary_file:

    test_file = temporary_file.name

try:
    # TEST 1: Create the CSV and write an alert.
    with open(
        test_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "Time",
            "Alert Type",
            "Source IP",
            "Destination IP",
            "Message"
        ])

        log_alert(
            writer,
            "Possible Port Scan",
            "192.168.1.10",
            "192.168.1.20",
            "10 unique destination ports observed"
        )

    print("\nTEST 1: Write an IDS alert")

    with open(
        test_file,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        rows = list(csv.reader(file))

    test1_passed = (
        len(rows) == 2
        and rows[1][1] == "Possible Port Scan"
        and rows[1][2] == "192.168.1.10"
        and rows[1][3] == "192.168.1.20"
    )

    print("CSV contains header and alert:", len(rows) == 2)
    print("Alert details are correct:", test1_passed)
    print("Test result:", "PASSED" if test1_passed else "FAILED")

    # TEST 2: Verify another alert can be appended.
    with open(
        test_file,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        log_alert(
            writer,
            "Traffic Spike",
            "192.168.1.30",
            "192.168.1.40",
            "High packet count observed"
        )

    with open(
        test_file,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        rows = list(csv.reader(file))

    test2_passed = (
        len(rows) == 3
        and rows[2][1] == "Traffic Spike"
    )

    print("\nTEST 2: Append a second alert")
    print("Total CSV rows, including header:", len(rows))
    print("Second alert recorded correctly:", test2_passed)
    print("Test result:", "PASSED" if test2_passed else "FAILED")

    print("\n" + "=" * 55)

    if test1_passed and test2_passed:
        print("RESULT: BOTH IDS LOGGING TESTS PASSED!")
    else:
        print("RESULT: ONE OR MORE TESTS FAILED")

    print("=" * 55)

finally:
    if os.path.exists(test_file):
        os.remove(test_file)

print("Temporary test file cleaned up.")
print("Your project CSV files were not modified.")
