import pandas as pd
import matplotlib.pyplot as plt


# ========================================
# LOAD NETWORK TRAFFIC DATA
# ========================================

file_name = "network_traffic.csv"

data = pd.read_csv(file_name)


# ========================================
# PROJECT TITLE
# ========================================

print()
print("========================================")
print("       NETWORK TRAFFIC ANALYSIS")
print("========================================")
print()


# ========================================
# BASIC INFORMATION
# ========================================

print("Total Packets :", len(data))

print()


# ========================================
# PROTOCOL ANALYSIS
# ========================================

print("------------- PROTOCOL ANALYSIS --------")

protocol_counts = data["Protocol"].value_counts()

for protocol, count in protocol_counts.items():

    print(protocol, "Packets :", count)

print()


# ========================================
# IP VERSION ANALYSIS
# ========================================

print("------------- IP ANALYSIS --------------")

ipv4_count = 0
ipv6_count = 0

for ip in data["Source IP"]:

    if ":" in str(ip):
        ipv6_count += 1
    else:
        ipv4_count += 1

print("IPv4 Packets :", ipv4_count)
print("IPv6 Packets :", ipv6_count)

print()


# ========================================
# SERVICE ANALYSIS
# ========================================

print("------------- SERVICE ANALYSIS ----------")

service_counts = data["Service"].value_counts()

for service, count in service_counts.head(10).items():

    print(service, ":", count)

print()


# ========================================
# PACKET SIZE ANALYSIS
# ========================================

print("------------- PACKET SIZE ---------------")

average_size = data["Packet Size"].mean()

maximum_size = data["Packet Size"].max()

minimum_size = data["Packet Size"].min()

print("Average Packet Size :", round(average_size, 2), "bytes")

print("Maximum Packet Size :", maximum_size, "bytes")

print("Minimum Packet Size :", minimum_size, "bytes")

print()


# ========================================
# TOP SOURCE IPs
# ========================================

print("------------- TOP SOURCE IPs ------------")

source_counts = data["Source IP"].value_counts()

for ip, count in source_counts.head(5).items():

    print(ip, ":", count, "packets")

print()


# ========================================
# TOP DESTINATION IPs
# ========================================

print("---------- TOP DESTINATION IPs ----------")

destination_counts = data["Destination IP"].value_counts()

for ip, count in destination_counts.head(5).items():

    print(ip, ":", count, "packets")

print()


# ========================================
# GRAPH 1
# PROTOCOL DISTRIBUTION
# ========================================

plt.figure()

protocol_counts.plot(
    kind="bar"
)

plt.title("Network Protocol Distribution")

plt.xlabel("Protocol")

plt.ylabel("Number of Packets")

plt.xticks(rotation=0)

plt.tight_layout()

plt.show()


# ========================================
# GRAPH 2
# IPv4 vs IPv6
# ========================================

ip_versions = {
    "IPv4": ipv4_count,
    "IPv6": ipv6_count
}

plt.figure()

plt.bar(
    ip_versions.keys(),
    ip_versions.values()
)

plt.title("IP Version Distribution")

plt.xlabel("IP Version")

plt.ylabel("Number of Packets")

plt.tight_layout()

plt.show()


# ========================================
# GRAPH 3
# TOP NETWORK SERVICES
# ========================================

top_services = service_counts.head(10)

plt.figure()

top_services.plot(
    kind="bar"
)

plt.title("Top Network Services")

plt.xlabel("Service")

plt.ylabel("Number of Packets")

plt.xticks(rotation=45)

plt.tight_layout()

plt.show()


# ========================================
# GRAPH 4
# PACKET SIZE DISTRIBUTION
# ========================================

plt.figure()

plt.hist(
    data["Packet Size"],
    bins=20
)

plt.title("Packet Size Distribution")

plt.xlabel("Packet Size (bytes)")

plt.ylabel("Number of Packets")

plt.tight_layout()

plt.show()


# ========================================
# GRAPH 5
# TOP SOURCE IPs
# ========================================

top_sources = source_counts.head(5)

plt.figure()

top_sources.plot(
    kind="bar"
)

plt.title("Top Source IP Addresses")

plt.xlabel("Source IP")

plt.ylabel("Number of Packets")

plt.xticks(rotation=45)

plt.tight_layout()

plt.show()


# ========================================
# FINAL REPORT
# ========================================

print("========================================")
print("       VISUAL ANALYSIS COMPLETE")
print("========================================")