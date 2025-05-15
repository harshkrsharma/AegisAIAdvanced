from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime
import csv, math, time
import geoip2.database
import os
import hashlib

# Load GeoIP DB
GEOIP_DB_PATH = "GeoLite2-City.mmdb"
# reader = geoip2.database.Reader(GEOIP_DB_PATH)

# Flow state store: (src, dst, sport, dport, proto) => stats
flow_stats = {}
last_packet_time = {}

# Payload entropy
def calculate_entropy(payload):
    if not payload:
        return 0
    byte_freq = [0] * 256
    for byte in payload:
        byte_freq[byte] += 1
    entropy = 0
    for freq in byte_freq:
        if freq > 0:
            p = freq / len(payload)
            entropy -= p * math.log2(p)
    return round(entropy, 4)

# Get country from IP
def get_geo_location(ip):
    if not os.path.exists(GEOIP_DB_PATH):
        print(f"[!] GeoIP database not found: {GEOIP_DB_PATH}")
        return "Unknown"

    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip)
            country = response.country.name
            city = response.city.name or "Unknown City"
            return f"{city}, {country}"
    except Exception as e:
        print(f"[!] GeoIP lookup failed for IP {ip}: {e}")
        return "Unknown"

# Get Direction (Internal/External)
def get_direction(ip):
    # Assuming internal IPs follow common private IP patterns
    if ip.startswith(("192.168.", "10.", "172.")):
        return "Internal"
    return "External"

# Generate flow ID (hash of the 5-tuple)
def generate_flow_id(src, dst, sport, dport, proto):
    return hashlib.md5(f"{src}-{dst}-{sport}-{dport}-{proto}".encode()).hexdigest()

# Packet callback
def packet_callback(packet):
    try:
        timestamp = time.time()
        timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

        if IP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        proto = {6: "TCP", 17: "UDP"}.get(proto_num, "Other")
        sport = packet.sport if TCP in packet or UDP in packet else None
        dport = packet.dport if TCP in packet or UDP in packet else None
        pkt_size = len(packet)
        ttl = packet[IP].ttl
        flags = packet[TCP].flags if TCP in packet else None
        entropy = calculate_entropy(bytes(packet[Raw].load) if Raw in packet else b"")
        
        # Direction (Internal/External)
        direction = get_direction(src_ip)

        # Inter-arrival time
        key = (src_ip, dst_ip, sport, dport, proto)
        iat = timestamp - last_packet_time.get(key, timestamp)
        last_packet_time[key] = timestamp

        # Update flow stats
        if key not in flow_stats:
            flow_stats[key] = {
                "first_seen": timestamp,
                "bytes": pkt_size
            }
        else:
            flow_stats[key]["bytes"] += pkt_size
        session_duration = timestamp - flow_stats[key]["first_seen"]
        total_bytes = flow_stats[key]["bytes"]

        # Geolocation
        src_country = get_geo_location(src_ip)
        dst_country = get_geo_location(dst_ip)

        # Generate flow ID
        flow_id = generate_flow_id(src_ip, dst_ip, sport, dport, proto)

        # MAC Address info (Ethernet Layer)
        src_mac = packet.src if packet.haslayer("Ethernet") else None
        dst_mac = packet.dst if packet.haslayer("Ethernet") else None

        # Write to CSV
        with open("network_traffic.csv", "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([ 
                timestamp_str, src_ip, dst_ip, sport, dport, proto,
                pkt_size, ttl, flags, entropy, round(iat, 6),
                round(session_duration, 2), total_bytes,
                src_country, dst_country, direction, flow_id,
                src_mac, dst_mac
            ])

    except Exception as e:
        print(f"Error: {e}")

# CSV Header
with open("network_traffic.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([ 
        "Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol",
        "Packet Size", "TTL", "TCP Flags", "Payload Entropy",
        "Inter-Arrival Time", "Session Duration", "Bytes Transferred",
        "Src Country", "Dst Country", "Direction", "Flow ID",
        "Src MAC", "Dst MAC"
    ])

print("[*] Full-feature packet capture started...")
sniff(prn=packet_callback, store=0)
