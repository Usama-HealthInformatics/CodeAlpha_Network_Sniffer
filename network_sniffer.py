from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP

INTERFACE = "Intel(R) Wi-Fi 6E AX211 160MHz"

stats = {
    "Total": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "ARP": 0,
    "Other": 0,
    "Alerts": 0
}

SECURITY_PORTS = {
    21: ("FTP", "MEDIUM"),
    23: ("Telnet", "HIGH"),
    445: ("SMB", "MEDIUM"),
    3389: ("RDP", "MEDIUM"),
}


def get_addresses(packet):
    source = "-"
    destination = "-"

    if packet.haslayer(IP):
        source = packet[IP].src
        destination = packet[IP].dst

    elif packet.haslayer(IPv6):
        source = packet[IPv6].src
        destination = packet[IPv6].dst

    return source, destination


def get_ports(packet):
    source_port = None
    destination_port = None

    if packet.haslayer(TCP):
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    return source_port, destination_port


def identify_service(packet):

    source_port, destination_port = get_ports(packet)

    ports = [source_port, destination_port]

    for port in ports:

        if port is None:
            continue

        if port == 21:
            return "FTP"

        if port == 23:
            return "Telnet"

        if port == 22:
            return "SSH"

        if port == 25:
            return "SMTP"

        if port == 53:
            return "DNS"

        if port == 80:
            return "HTTP"

        if port == 110:
            return "POP3"

        if port == 143:
            return "IMAP"

        if port == 443:
            if packet.haslayer(UDP):
                return "QUIC"
            return "HTTPS/TLS"

        if port == 445:
            return "SMB"

        if port == 3389:
            return "RDP"

        if port == 123:
            return "NTP"

        if port == 161:
            return "SNMP"

        if port == 1900:
            return "SSDP"

    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(ARP):
        return "ARP"

    return "Other"


def write_security_event(
    severity,
    service,
    direction,
    source,
    destination,
    port
):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    event = (
        f"{timestamp} | "
        f"Severity={severity} | "
        f"Service={service} | "
        f"Direction={direction} | "
        f"Source={source} | "
        f"Destination={destination} | "
        f"Port={port}"
    )

    with open(
        "security_alerts.log",
        "a",
        encoding="utf-8"
    ) as log:

        log.write(event + "\n")

    print()
    print("!" * 110)
    print("[SECURITY ALERT]")
    print(event)
    print("Event saved to security_alerts.log")
    print("!" * 110)


def check_security_alert(packet):

    source, destination = get_addresses(packet)

    source_port, destination_port = get_ports(packet)

    if source_port is None or destination_port is None:
        return

    # Check destination port
    if destination_port in SECURITY_PORTS:

        service, severity = SECURITY_PORTS[destination_port]

        stats["Alerts"] += 1

        write_security_event(
            severity,
            service,
            "OUTBOUND",
            source,
            destination,
            destination_port
        )

    # Check source port
    elif source_port in SECURITY_PORTS:

        service, severity = SECURITY_PORTS[source_port]

        stats["Alerts"] += 1

        write_security_event(
            severity,
            service,
            "INBOUND/RESPONSE",
            source,
            destination,
            source_port
        )


def packet_callback(packet):

    stats["Total"] += 1

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    source, destination = get_addresses(packet)

    source_port, destination_port = get_ports(packet)

    protocol = "Other"

    if packet.haslayer(TCP):

        protocol = "TCP"
        stats["TCP"] += 1

    elif packet.haslayer(UDP):

        protocol = "UDP"
        stats["UDP"] += 1

    elif packet.haslayer(ICMP):

        protocol = "ICMP"
        stats["ICMP"] += 1

    elif packet.haslayer(ARP):

        protocol = "ARP"
        stats["ARP"] += 1

    else:

        stats["Other"] += 1

    service = identify_service(packet)

    check_security_alert(packet)

    print(
        f"{timestamp} | "
        f"{source:<39} -> "
        f"{destination:<39} | "
        f"{protocol:<5} | "
        f"{service:<10} | "
        f"{str(source_port):<6} -> "
        f"{str(destination_port):<6} | "
        f"{len(packet)} bytes"
    )


print("=" * 130)
print("CodeAlpha - Basic Network Sniffer V8")
print("Bidirectional Security Detection")
print("=" * 130)

print("Interface:", INTERFACE)
print("Security monitoring enabled.")
print("Monitoring source AND destination ports.")
print("Alerts saved to: security_alerts.log")
print("Press CTRL+C to stop.")
print("-" * 130)

try:

    sniff(
        iface=INTERFACE,
        prn=packet_callback,
        store=False
    )

except KeyboardInterrupt:

    print("\n\nCapture stopped by user.")

finally:

    print("\n" + "=" * 50)
    print("PACKET CAPTURE SUMMARY")
    print("=" * 50)

    print(f"Total Packets   : {stats['Total']}")
    print(f"TCP             : {stats['TCP']}")
    print(f"UDP             : {stats['UDP']}")
    print(f"ICMP            : {stats['ICMP']}")
    print(f"ARP             : {stats['ARP']}")
    print(f"Other           : {stats['Other']}")
    print(f"Security Alerts : {stats['Alerts']}")

    print("=" * 50)