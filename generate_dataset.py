import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import hashlib

def generate_flow_id(src_ip, dst_ip, sport, dport, proto):
    return hashlib.md5(f"{src_ip}-{dst_ip}-{sport}-{dport}-{proto}".encode()).hexdigest()

def generate_normal_traffic(num_records):
    data = []
    base_time = datetime.now()
    
    # Common internal IP ranges
    internal_ips = [f"192.168.1.{i}" for i in range(1, 200)]
    external_ips = [f"8.8.8.{i}" for i in range(1, 100)]  # Example external IPs
    
    # Common ports and their typical protocols
    common_ports = {
        80: "TCP",  # HTTP
        443: "TCP",  # HTTPS
        22: "TCP",   # SSH
        53: "UDP",   # DNS
        3389: "TCP", # RDP
        3306: "TCP", # MySQL
        1433: "TCP", # MSSQL
        21: "TCP",   # FTP
        25: "TCP",   # SMTP
        110: "TCP",  # POP3
        143: "TCP",  # IMAP
        445: "TCP",  # SMB
        139: "TCP",  # NetBIOS
        161: "UDP",  # SNMP
        162: "UDP",  # SNMP Trap
        389: "TCP",  # LDAP
        636: "TCP",  # LDAPS
        88: "TCP",   # Kerberos
        464: "TCP",  # Kerberos password change
        88: "UDP",   # Kerberos
        464: "UDP"   # Kerberos password change
    }
    
    for _ in range(num_records):
        # Add some randomness to make patterns less distinct
        is_noisy = random.random() < 0.15  # 15% chance of noisy behavior
        
        # Generate normal traffic patterns
        timestamp = base_time + timedelta(seconds=random.uniform(0, 86400))
        src_ip = random.choice(internal_ips)
        dst_ip = random.choice(external_ips)
        sport = random.randint(49152, 65535)
        dport, proto = random.choice(list(common_ports.items()))
        
        # Add some variation to packet sizes
        if is_noisy:
            pkt_size = random.randint(1500, 3000)  # Occasionally larger packets
            ttl = random.randint(32, 64)  # Occasionally lower TTL
            entropy = random.uniform(6.5, 7.5)  # Occasionally higher entropy
            iat = random.uniform(0.0001, 0.01)  # Occasionally faster traffic
        else:
            pkt_size = random.randint(40, 1500)
            ttl = random.randint(64, 128)
            entropy = random.uniform(3.0, 7.0)
            iat = random.uniform(0.001, 1.0)
        
        flags = random.choice(["S", "A", "PA", "F", "R"]) if proto == "TCP" else None
        session_duration = random.uniform(1, 300)
        total_bytes = pkt_size * random.randint(1, 100)
        src_country = "Internal"
        dst_country = random.choice(["United States", "Germany", "United Kingdom", "Japan", "Canada", "France", "Australia"])
        direction = "Internal"
        flow_id = generate_flow_id(src_ip, dst_ip, sport, dport, proto)
        src_mac = f"00:1A:2B:{random.randint(10,99):02d}:{random.randint(10,99):02d}:{random.randint(10,99):02d}"
        dst_mac = f"00:1C:2D:{random.randint(10,99):02d}:{random.randint(10,99):02d}:{random.randint(10,99):02d}"
        
        data.append([
            timestamp, src_ip, dst_ip, sport, dport, proto,
            pkt_size, ttl, flags, entropy, iat,
            session_duration, total_bytes,
            src_country, dst_country, direction, flow_id,
            src_mac, dst_mac
        ])
    
    return data

def generate_anomalous_traffic(num_records):
    data = []
    base_time = datetime.now()
    
    # Anomalous IP patterns
    internal_ips = [f"192.168.1.{i}" for i in range(1, 200)]
    suspicious_ips = (
        [f"45.67.89.{i}" for i in range(1, 50)] +  # Suspicious external IPs
        [f"185.143.223.{i}" for i in range(1, 50)] +  # Known malicious IP ranges
        [f"91.234.36.{i}" for i in range(1, 50)] +
        [f"193.169.245.{i}" for i in range(1, 50)]
    )
    
    # Common attack ports and patterns
    attack_patterns = [
        # Port scanning
        {"ports": [21, 22, 23, 25, 53, 80, 443, 445, 3389], "proto": "TCP", "flags": "S", "pkt_size": 40, "iat": 0.0001},
        # DDoS
        {"ports": [80, 443], "proto": "TCP", "flags": "S", "pkt_size": 1500, "iat": 0.00001},
        # Data exfiltration
        {"ports": [443, 8443], "proto": "TCP", "flags": "PA", "pkt_size": 9000, "iat": 0.1},
        # Brute force
        {"ports": [22, 3389], "proto": "TCP", "flags": "S", "pkt_size": 60, "iat": 0.01},
        # DNS tunneling
        {"ports": [53], "proto": "UDP", "flags": None, "pkt_size": 512, "iat": 0.1},
        # Insider data theft (using normal ports)
        {"ports": [443, 445, 3389], "proto": "TCP", "flags": "PA", "pkt_size": 1500, "iat": 0.1},
        # Lateral movement
        {"ports": [445, 3389, 5985], "proto": "TCP", "flags": "S", "pkt_size": 60, "iat": 0.01},
        # Credential dumping
        {"ports": [445, 139], "proto": "TCP", "flags": "PA", "pkt_size": 1000, "iat": 0.05}
    ]
    
    for _ in range(num_records):
        # Add some randomness to make patterns less distinct
        is_stealthy = random.random() < 0.3  # 30% chance of stealthy attack
        is_insider = random.random() < 0.2  # 20% chance of insider attack
        
        # Select an attack pattern
        pattern = random.choice(attack_patterns)
        
        # Generate anomalous traffic patterns
        timestamp = base_time + timedelta(seconds=random.uniform(0, 86400))
        src_ip = random.choice(internal_ips)
        
        if is_insider:
            # Insider attack - use internal IPs
            dst_ip = random.choice(internal_ips)
            # Use normal-looking patterns but with malicious intent
            pkt_size = random.randint(40, 1500)
            ttl = random.randint(64, 128)
            flags = random.choice(["S", "A", "PA"]) if pattern["proto"] == "TCP" else None
            entropy = random.uniform(3.0, 7.0)
            iat = random.uniform(0.001, 1.0)
            # Use sensitive internal ports
            dport = random.choice([445, 3389, 5985, 1433, 3306])  # SMB, RDP, WinRM, SQL
        else:
            dst_ip = random.choice(suspicious_ips)
            if is_stealthy:
                # Make the attack look more like normal traffic
                pkt_size = random.randint(40, 1500)
                ttl = random.randint(64, 128)
                flags = random.choice(["S", "A", "PA"]) if pattern["proto"] == "TCP" else None
                entropy = random.uniform(3.0, 7.0)
                iat = random.uniform(0.001, 1.0)
            else:
                pkt_size = pattern["pkt_size"]
                ttl = random.randint(1, 10)
                flags = pattern["flags"]
                entropy = random.uniform(7.5, 8.0)
                iat = pattern["iat"]
            dport = random.choice(pattern["ports"])
        
        sport = random.randint(49152, 65535)
        proto = pattern["proto"]
        session_duration = random.uniform(0.1, 1)
        total_bytes = pkt_size * random.randint(100, 1000)
        src_country = "Internal"
        dst_country = "Internal" if is_insider else random.choice(["Russia", "China", "North Korea", "Iran", "Unknown"])
        direction = "Internal"
        flow_id = generate_flow_id(src_ip, dst_ip, sport, dport, proto)
        src_mac = f"00:1A:2B:{random.randint(10,99):02d}:{random.randint(10,99):02d}:{random.randint(10,99):02d}"
        dst_mac = f"00:1C:2D:{random.randint(10,99):02d}:{random.randint(10,99):02d}:{random.randint(10,99):02d}"
        
        data.append([
            timestamp, src_ip, dst_ip, sport, dport, proto,
            pkt_size, ttl, flags, entropy, iat,
            session_duration, total_bytes,
            src_country, dst_country, direction, flow_id,
            src_mac, dst_mac
        ])
    
    return data

def main():
    # Generate 95,000 normal records and 5,000 anomalous records (5% anomalous)
    normal_data = generate_normal_traffic(95000)
    anomalous_data = generate_anomalous_traffic(5000)
    
    # Combine the data
    all_data = normal_data + anomalous_data
    
    # Create DataFrame
    columns = [
        "Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol",
        "Packet Size", "TTL", "TCP Flags", "Payload Entropy",
        "Inter-Arrival Time", "Session Duration", "Bytes Transferred",
        "Src Country", "Dst Country", "Direction", "Flow ID",
        "Src MAC", "Dst MAC"
    ]
    
    df = pd.DataFrame(all_data, columns=columns)
    
    # Add label column (0 for normal, 1 for anomalous)
    df['Label'] = [0] * len(normal_data) + [1] * len(anomalous_data)
    
    # Shuffle the dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save to CSV
    df.to_csv('synthetic_network_traffic_large.csv', index=False)
    print(f"Generated dataset with {len(normal_data)} normal records and {len(anomalous_data)} anomalous records")
    print(f"Total records: {len(df)}")
    print(f"Anomaly percentage: {(len(anomalous_data)/len(df))*100:.2f}%")
    print("\nAttack Distribution:")
    print(f"- External attacks: {int(len(anomalous_data) * 0.8)}")
    print(f"- Insider attacks: {int(len(anomalous_data) * 0.2)}")
    print(f"- Stealthy attacks: {int(len(anomalous_data) * 0.3)}")

if __name__ == "__main__":
    main() 