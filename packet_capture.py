from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
import csv
import os
import time
from datetime import datetime
from collections import defaultdict, deque


# ============================================================
# NETWORK TRAFFIC ANALYZER AND INTRUSION DETECTION SYSTEM
# ============================================================

TRAFFIC_CSV = "network_traffic.csv"
ALERTS_CSV = "ids_alerts.csv"

# Detection thresholds
PORT_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW_SECONDS = 10

TRAFFIC_SPIKE_THRESHOLD = 100
TRAFFIC_SPIKE_WINDOW_SECONDS = 10

REPEATED_CONNECTION_THRESHOLD = 5
REPEATED_CONNECTION_WINDOW_SECONDS = 10

ICMP_THRESHOLD = 20
ICMP_WINDOW_SECONDS = 10

ALERT_COOLDOWN_SECONDS = 10

# Connections to these ports generate monitoring alerts.
# A monitored port is not automatically malicious.
MONITORED_PORTS = {
    21, 22, 23, 445, 1433, 3306, 3389, 4444
}


# ============================================================
# TRAFFIC STATISTICS
# ============================================================

stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "ipv4": 0,
    "ipv6": 0,
    "icmp": 0
}

alert_counts = {
    "port_scan": 0,
    "traffic_spike": 0,
    "repeated_connection": 0,
    "monitored_port": 0,
    "icmp": 0
}

port_scan_alerts = 0
traffic_spike_alerts = 0
repeated_connection_alerts = 0
monitored_port_alerts = 0
icmp_alerts = 0


# ============================================================
# IDS DETECTION MEMORY
# ============================================================

# Source IP -> deque of (timestamp, destination port)
recent_ports = defaultdict(deque)

# Detection key -> last alert time
last_alert_time = {}

# Time-window counters
recent_packet_times = deque()
recent_connections = defaultdict(deque)
recent_icmp_times = defaultdict(deque)

# Prevent test imports from starting live capture.
CAPTURE_ACTIVE = False

# CSV handles are opened only when live capture starts.
csv_file = None
csv_writer = None

alert_file = None
alert_writer = None


# ============================================================
# CSV HEADERS
# ============================================================

TRAFFIC_HEADERS = [
    "Time",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Service",
    "Packet Size"
]

ALERT_HEADERS = [
    "Time",
    "Alert Type",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Unique Destination Ports",
    "Observed Ports",
    "Time Window Seconds",
    "Message"
]


# ============================================================
# OPEN CSV FILES SAFELY
# ============================================================

def ensure_files_open(reset=False):
    """
    Open CSV files when needed.

    reset=True starts new CSV files for a new live capture.
    reset=False reopens closed files in append mode.
    """

    global csv_file, csv_writer
    global alert_file, alert_writer

    if csv_file is None or csv_file.closed:
        mode = "w" if reset else "a"
        file_exists = os.path.exists(TRAFFIC_CSV)
        has_content = (
            file_exists and os.path.getsize(TRAFFIC_CSV) > 0
        )

        csv_file = open(
            TRAFFIC_CSV,
            mode,
            newline="",
            encoding="utf-8"
        )

        csv_writer = csv.writer(csv_file)

        if reset or not has_content:
            csv_writer.writerow(TRAFFIC_HEADERS)

    if alert_file is None or alert_file.closed:
        mode = "w" if reset else "a"
        file_exists = os.path.exists(ALERTS_CSV)
        has_content = (
            file_exists and os.path.getsize(ALERTS_CSV) > 0
        )

        alert_file = open(
            ALERTS_CSV,
            mode,
            newline="",
            encoding="utf-8"
        )

        alert_writer = csv.writer(alert_file)

        if reset or not has_content:
            alert_writer.writerow(ALERT_HEADERS)


# ============================================================
# IDENTIFY COMMON NETWORK SERVICES
# ============================================================

def identify_service(port):

    services = {
        20: "FTP-Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        4444: "Monitored Port"
    }

    return services.get(port, "Unknown")


# ============================================================
# DETECT ICMP AND ICMPv6 WITHOUT IMPORTING ICMPv6
# ============================================================

def is_icmp_packet(packet):

    if packet.haslayer(ICMP):
        return True

    # Check IPv6 layers by their class names.
    # This avoids the unavailable "ICMPv6" import.
    try:
        for layer in packet.layers():
            if layer.__class__.__name__.startswith("ICMPv6"):
                return True
    except Exception:
        pass

    return False


# ============================================================
# WRITE IDS ALERT
# ============================================================

def log_alert(
    alert_type,
    source,
    destination,
    protocol,
    unique_ports,
    observed_ports,
    window_seconds,
    message
):

    global alert_file, alert_writer

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print()
    print("!" * 55)
    print("IDS ALERT:", alert_type)
    print("Time:", timestamp)
    print("Source IP:", source)
    print("Destination IP:", destination)
    print("Protocol:", protocol)
    print("Observed Ports:", observed_ports)
    print("Message:", message)
    print("!" * 55)
    print()

    # During live capture, write alerts to the project CSV.
    # Tests can replace alert_file and alert_writer with in-memory
    # objects, so test packets do not overwrite project files.
    if CAPTURE_ACTIVE:
        ensure_files_open()

    if (
        alert_file is not None
        and alert_writer is not None
        and not alert_file.closed
    ):
        alert_writer.writerow([
            timestamp,
            alert_type,
            source,
            destination,
            protocol,
            unique_ports,
            observed_ports,
            window_seconds,
            message
        ])

        if hasattr(alert_file, "flush"):
            alert_file.flush()


# ============================================================
# ALERT COOLDOWN
# ============================================================

def can_alert(key):

    current_time = time.time()
    previous_time = last_alert_time.get(key)

    if previous_time is None:
        last_alert_time[key] = current_time
        return True

    if current_time - previous_time >= ALERT_COOLDOWN_SECONDS:
        last_alert_time[key] = current_time
        return True

    return False


# ============================================================
# PORT SCAN DETECTION
# ============================================================

def detect_port_scan(packet, source, destination, protocol):

    global port_scan_alerts

    if not packet.haslayer(TCP):
        return

    tcp_layer = packet[TCP]

    # Only count TCP SYN packets that are not ACK responses.
    # This helps avoid treating ordinary TCP responses as scans.
    flags = int(tcp_layer.flags)

    syn_set = bool(flags & 0x02)
    ack_set = bool(flags & 0x10)

    if not syn_set or ack_set:
        return

    current_time = time.time()
    destination_port = int(tcp_layer.dport)

    port_queue = recent_ports[source]

    port_queue.append((current_time, destination_port))

    # Remove entries outside the detection window.
    while (
        port_queue
        and current_time - port_queue[0][0]
        > PORT_SCAN_WINDOW_SECONDS
    ):
        port_queue.popleft()

    unique_ports = sorted({
        port for timestamp, port in port_queue
    })

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:

        alert_key = ("port_scan", source)

        if can_alert(alert_key):

            port_scan_alerts += 1
            alert_counts["port_scan"] += 1

            log_alert(
                alert_type="Possible Port Scan Detected",
                source=source,
                destination=destination,
                protocol=protocol,
                unique_ports=len(unique_ports),
                observed_ports=", ".join(map(str, unique_ports)),
                window_seconds=PORT_SCAN_WINDOW_SECONDS,
                message=(
                    f"One source contacted "
                    f"{len(unique_ports)} distinct destination ports "
                    f"within {PORT_SCAN_WINDOW_SECONDS} seconds."
                )
            )


# ============================================================
# TRAFFIC SPIKE DETECTION
# ============================================================

def detect_traffic_spike(source, destination, protocol):

    global traffic_spike_alerts

    current_time = time.time()

    recent_packet_times.append(
        (current_time, source, destination, protocol)
    )

    while (
        recent_packet_times
        and current_time - recent_packet_times[0][0]
        > TRAFFIC_SPIKE_WINDOW_SECONDS
    ):
        recent_packet_times.popleft()

    packet_count = len(recent_packet_times)

    if packet_count >= TRAFFIC_SPIKE_THRESHOLD:

        alert_key = ("traffic_spike", "overall")

        if can_alert(alert_key):

            traffic_spike_alerts += 1
            alert_counts["traffic_spike"] += 1

            log_alert(
                alert_type="Possible Traffic Spike",
                source=source,
                destination=destination,
                protocol=protocol,
                unique_ports=0,
                observed_ports="N/A",
                window_seconds=TRAFFIC_SPIKE_WINDOW_SECONDS,
                message=(
                    f"{packet_count} packets observed within "
                    f"{TRAFFIC_SPIKE_WINDOW_SECONDS} seconds."
                )
            )


# ============================================================
# REPEATED CONNECTION DETECTION
# ============================================================

def detect_repeated_connection(
    source,
    destination,
    destination_port,
    protocol
):

    global repeated_connection_alerts

    current_time = time.time()

    connection_key = (
        source,
        destination,
        destination_port,
        protocol
    )

    connection_queue = recent_connections[connection_key]
    connection_queue.append(current_time)

    while (
        connection_queue
        and current_time - connection_queue[0]
        > REPEATED_CONNECTION_WINDOW_SECONDS
    ):
        connection_queue.popleft()

    if len(connection_queue) >= REPEATED_CONNECTION_THRESHOLD:

        alert_key = ("repeated_connection", connection_key)

        if can_alert(alert_key):

            repeated_connection_alerts += 1
            alert_counts["repeated_connection"] += 1

            log_alert(
                alert_type="Repeated Connection Attempts",
                source=source,
                destination=destination,
                protocol=protocol,
                unique_ports=1,
                observed_ports=str(destination_port),
                window_seconds=REPEATED_CONNECTION_WINDOW_SECONDS,
                message=(
                    f"{len(connection_queue)} packets observed for "
                    f"the same endpoint and destination port within "
                    f"{REPEATED_CONNECTION_WINDOW_SECONDS} seconds."
                )
            )


# ============================================================
# MONITORED PORT DETECTION
# ============================================================

def detect_monitored_port(
    source,
    destination,
    source_port,
    destination_port,
    protocol
):

    global monitored_port_alerts

    matching_ports = []

    if destination_port in MONITORED_PORTS:
        matching_ports.append(destination_port)

    if source_port in MONITORED_PORTS:
        matching_ports.append(source_port)

    if not matching_ports:
        return

    for port in set(matching_ports):

        alert_key = (
            "monitored_port",
            source,
            destination,
            port
        )

        if can_alert(alert_key):

            monitored_port_alerts += 1
            alert_counts["monitored_port"] += 1

            log_alert(
                alert_type="Monitored Port Observed",
                source=source,
                destination=destination,
                protocol=protocol,
                unique_ports=1,
                observed_ports=str(port),
                window_seconds=0,
                message=(
                    f"Traffic involving monitored port {port} "
                    f"({identify_service(port)}) was observed."
                )
            )


# ============================================================
# EXCESSIVE ICMP DETECTION
# ============================================================

def detect_icmp(source, destination, protocol):

    global icmp_alerts

    if protocol not in ("ICMP", "ICMPv6"):
        return

    current_time = time.time()
    recent_icmp_times[source].append(current_time)

    queue = recent_icmp_times[source]

    while (
        queue
        and current_time - queue[0] > ICMP_WINDOW_SECONDS
    ):
        queue.popleft()

    if len(queue) >= ICMP_THRESHOLD:

        alert_key = ("icmp", source)

        if can_alert(alert_key):

            icmp_alerts += 1
            alert_counts["icmp"] += 1

            log_alert(
                alert_type="Possible Excessive ICMP Traffic",
                source=source,
                destination=destination,
                protocol=protocol,
                unique_ports=0,
                observed_ports="N/A",
                window_seconds=ICMP_WINDOW_SECONDS,
                message=(
                    f"{len(queue)} ICMP packets from the same source "
                    f"within {ICMP_WINDOW_SECONDS} seconds."
                )
            )


# ============================================================
# ANALYZE ONE PACKET
# ============================================================

def analyze_packet(packet):

    # Count packets even if they do not contain IP.
    stats["total"] += 1

    # --------------------------------------------------------
    # Get source and destination IP addresses
    # --------------------------------------------------------

    if packet.haslayer(IP):

        stats["ipv4"] += 1

        source = packet[IP].src
        destination = packet[IP].dst

    elif packet.haslayer(IPv6):

        stats["ipv6"] += 1

        source = packet[IPv6].src
        destination = packet[IPv6].dst

    else:
        return

    # --------------------------------------------------------
    # Default field values
    # --------------------------------------------------------

    protocol = "Other"
    source_port = "-"
    destination_port = "-"
    service = "Unknown"

    source_port_number = None
    destination_port_number = None

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if packet.haslayer(TCP):

        stats["tcp"] += 1

        protocol = "TCP"

        source_port_number = int(packet[TCP].sport)
        destination_port_number = int(packet[TCP].dport)

        source_port = source_port_number
        destination_port = destination_port_number

        service = identify_service(destination_port_number)

        if service == "Unknown":
            service = identify_service(source_port_number)

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    elif packet.haslayer(UDP):

        stats["udp"] += 1

        protocol = "UDP"

        source_port_number = int(packet[UDP].sport)
        destination_port_number = int(packet[UDP].dport)

        source_port = source_port_number
        destination_port = destination_port_number

        service = identify_service(destination_port_number)

        if service == "Unknown":
            service = identify_service(source_port_number)

    # --------------------------------------------------------
    # ICMP / ICMPv6
    # --------------------------------------------------------

    elif is_icmp_packet(packet):

        stats["icmp"] += 1

        if packet.haslayer(IP):
            protocol = "ICMP"
        else:
            protocol = "ICMPv6"

    # --------------------------------------------------------
    # Timestamp and packet size
    # --------------------------------------------------------

    timestamp_text = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    packet_size = len(packet)

    # --------------------------------------------------------
    # Display packet information
    # --------------------------------------------------------

    print("-" * 45)
    print("Time             :", timestamp_text)
    print("Source IP        :", source)
    print("Destination IP   :", destination)
    print("Protocol         :", protocol)
    print("Source Port      :", source_port)
    print("Destination Port :", destination_port)
    print("Service          :", service)
    print("Packet Size      :", packet_size, "bytes")

    # --------------------------------------------------------
    # Write traffic to CSV only during live capture
    # --------------------------------------------------------

    if CAPTURE_ACTIVE:

        ensure_files_open()

        csv_writer.writerow([
            timestamp_text,
            source,
            destination,
            protocol,
            source_port,
            destination_port,
            service,
            packet_size
        ])

        csv_file.flush()

    # --------------------------------------------------------
    # Run IDS detection rules
    # --------------------------------------------------------

    detect_port_scan(
        packet,
        source,
        destination,
        protocol
    )

    detect_traffic_spike(
        source,
        destination,
        protocol
    )

    if destination_port_number is not None:

        detect_repeated_connection(
            source,
            destination,
            destination_port_number,
            protocol
        )

    detect_monitored_port(
        source,
        destination,
        source_port_number,
        destination_port_number,
        protocol
    )

    detect_icmp(
        source,
        destination,
        protocol
    )


# ============================================================
# RESET IDS STATE FOR A NEW LIVE CAPTURE
# ============================================================

def reset_detection_state():

    global port_scan_alerts
    global traffic_spike_alerts
    global repeated_connection_alerts
    global monitored_port_alerts
    global icmp_alerts

    recent_ports.clear()
    last_alert_time.clear()
    recent_packet_times.clear()
    recent_connections.clear()
    recent_icmp_times.clear()

    for key in alert_counts:
        alert_counts[key] = 0

    port_scan_alerts = 0
    traffic_spike_alerts = 0
    repeated_connection_alerts = 0
    monitored_port_alerts = 0
    icmp_alerts = 0

    for key in stats:
        stats[key] = 0


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    global CAPTURE_ACTIVE

    print("=" * 55)
    print("       NETWORK TRAFFIC ANALYZER + IDS")
    print("=" * 55)

    print()
    print("Features enabled:")
    print("1. Live packet capture")
    print("2. TCP and UDP traffic analysis")
    print("3. IPv4 and IPv6 identification")
    print("4. Port scan detection")
    print("5. Traffic spike detection")
    print("6. Repeated connection detection")
    print("7. Monitored port alerts")
    print("8. Excessive ICMP detection")
    print("9. CSV traffic and alert logging")

    print()
    print("Only monitor networks you are authorized to inspect.")
    print("Press CTRL + C to stop capture.")
    print()

    reset_detection_state()

    # Start new CSV files for this live capture.
    ensure_files_open(reset=True)

    CAPTURE_ACTIVE = True

    try:

        sniff(
            prn=analyze_packet,
            store=False
        )

    except KeyboardInterrupt:

        print()
        print("Packet capture stopped by user.")

    except Exception as error:

        print()
        print("Packet capture error:", error)

    finally:

        CAPTURE_ACTIVE = False

        if csv_file is not None and not csv_file.closed:
            csv_file.close()

        if alert_file is not None and not alert_file.closed:
            alert_file.close()

        print()
        print("=" * 55)
        print("             TRAFFIC STATISTICS")
        print("=" * 55)

        print("Total Packets           :", stats["total"])
        print("TCP Packets             :", stats["tcp"])
        print("UDP Packets             :", stats["udp"])
        print("IPv4 Packets            :", stats["ipv4"])
        print("IPv6 Packets            :", stats["ipv6"])
        print("ICMP Packets            :", stats["icmp"])

        print()
        print("Port Scan Alerts        :", alert_counts["port_scan"])
        print("Traffic Spike Alerts    :", alert_counts["traffic_spike"])
        print(
            "Repeated Connection Alerts :",
            alert_counts["repeated_connection"]
        )
        print(
            "Monitored Port Alerts   :",
            alert_counts["monitored_port"]
        )
        print("ICMP Alerts              :", alert_counts["icmp"])

        print()
        print("Traffic CSV:", TRAFFIC_CSV)
        print("IDS Alerts CSV:", ALERTS_CSV)

        print("=" * 55)
        print("          ANALYZER TERMINATED")
        print("=" * 55)


# ============================================================
# START LIVE CAPTURE ONLY WHEN RUN DIRECTLY
# ============================================================

if __name__ == "__main__":
    main()