
"""
CodeAlpha Network Sniffer
Educational packet monitoring tool.

Test target:
- Windows 11
- Python 3.14
- Scapy 2.8.0
- Npcap installed for Windows packet capture

Only capture traffic on networks you own or are authorized to monitor.
"""

from collections import Counter
from datetime import datetime
from pathlib import Path
import time

from scapy.all import (
    sniff,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
)

# -------------------- CONFIGURATION --------------------

INTERFACE = "Intel(R) Wi-Fi 6E AX211 160MHz"

LOG_FILE = Path("security_alerts.log")
DEDUPLICATION_SECONDS = 60

# These are noteworthy ports, not proof of malicious activity.
OBSERVED_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
}

# The strings below are BPF capture filters supported by Scapy/Npcap.
FILTERS = {
    "1": ("All traffic", None),
    "2": ("TCP only", "tcp"),
    "3": ("UDP only", "udp"),
    "4": ("ICMP / ICMPv6", "icmp or icmp6"),
    "5": ("ARP only", "arp"),
    "6": ("DNS traffic", "port 53"),
    "7": ("HTTPS / QUIC traffic", "port 443"),
}

stats = Counter()
stats["Total"] = 0
stats["Alerts"] = 0
stats["Suppressed"] = 0

# Maps a flow signature to the time it was last logged.
recent_events = {}
packets_since_cleanup = 0
log_warning_shown = False


# -------------------- PACKET HELPERS --------------------

def get_addresses(packet):
    """Return source and destination addresses when available."""
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst

    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst

    if packet.haslayer(ARP):
        return packet[ARP].psrc, packet[ARP].pdst

    return "-", "-"


def get_ports(packet):
    """Return transport-layer ports, or None when unavailable."""
    if packet.haslayer(TCP):
        return packet[TCP].sport, packet[TCP].dport

    if packet.haslayer(UDP):
        return packet[UDP].sport, packet[UDP].dport

    return None, None



def identify_protocol(packet):
    """Classify a packet into one primary protocol category."""
    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    # ICMPv6 is IPv6's next-header protocol number 58.
    if packet.haslayer(IPv6):
        ipv6_packet = packet[IPv6]
        if ipv6_packet.nh == 58:
            return "ICMPv6"

        # Extension headers can precede ICMPv6, so check the
        # decoded payload chain as well.
        layer = ipv6_packet.payload
        while layer:
            if layer.__class__.__name__.startswith("ICMPv6"):
                return "ICMPv6"
            layer = getattr(layer, "payload", None)
            if layer is None or layer.__class__.__name__ == "NoPayload":
                break

    if packet.haslayer(ARP):
        return "ARP"

    return "Other"


def identify_service(packet):
    """Estimate a service using port numbers and packet layers."""
    source_port, destination_port = get_ports(packet)

    # Prefer the destination port because it often identifies
    # the service being contacted.
    for port in (destination_port, source_port):
        if port is None:
            continue

        if port in OBSERVED_PORTS:
            return OBSERVED_PORTS[port]

        if port == 25:
            return "SMTP"
        if port == 53:
            return "DNS"
        if port == 80:
            return "HTTP"
        if port == 110:
            return "POP3"
        if port == 123:
            return "NTP"
        if port == 143:
            return "IMAP"
        if port == 161:
            return "SNMP"
        if port == 1900:
            return "SSDP"
        if port == 443:
            if packet.haslayer(UDP):
                return "UDP/443 (possible QUIC)"
            return "TCP/443 (possible HTTPS/TLS)"

    return identify_protocol(packet)


# -------------------- OBSERVATION LOGGING --------------------

def make_flow_key(source, destination, source_port, destination_port,
                  service, observed_port):
    """Build a direction-independent key to suppress repeated events."""
    endpoint_a = (source, source_port)
    endpoint_b = (destination, destination_port)

    endpoints = tuple(sorted((endpoint_a, endpoint_b)))

    return service, observed_port, endpoints


def write_observation(service, source, destination,
                      source_port, destination_port, observed_port):
    """
    Log a noteworthy port observation once per flow per cooldown.
    This is not an attack verdict.
    """
    global packets_since_cleanup, log_warning_shown

    now = time.monotonic()
    key = make_flow_key(
        source, destination, source_port, destination_port,
        service, observed_port
    )

    last_seen = recent_events.get(key)

    if last_seen is not None and now - last_seen < DEDUPLICATION_SECONDS:
        stats["Suppressed"] += 1
        return

    recent_events[key] = now
    stats["Alerts"] += 1

    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")

    event = (
        f"{timestamp} | "
        f"Type=PORT_OBSERVATION | "
        f"Service={service} | "
        f"Source={source}:{source_port} | "
        f"Destination={destination}:{destination_port} | "
        f"ObservedPort={observed_port} | "
        f"Note=Port usage alone does not indicate malicious activity"
    )

    print("\n" + "-" * 100)
    print("[PORT OBSERVATION]")
    print(event)
    print("-" * 100)

    try:
        with LOG_FILE.open("a", encoding="utf-8") as log:
            log.write(event + "\n")
    except OSError as exc:
        if not log_warning_shown:
            print(
                f"[WARNING] Could not write {LOG_FILE}: {exc}. "
                "Further file-write warnings are suppressed."
            )
            log_warning_shown = True

    packets_since_cleanup += 1

    # Periodically remove old keys so memory use stays bounded.
    if packets_since_cleanup >= 100:
        cutoff = now - DEDUPLICATION_SECONDS
        expired = [
            event_key
            for event_key, last_seen_time in recent_events.items()
            if last_seen_time < cutoff
        ]

        for event_key in expired:
            del recent_events[event_key]

        packets_since_cleanup = 0


def check_port_observation(packet, source, destination,
                           source_port, destination_port):
    """Record use of selected ports without guessing traffic direction."""
    candidates = []

    if destination_port in OBSERVED_PORTS:
        candidates.append((destination_port, OBSERVED_PORTS[destination_port]))

    if source_port in OBSERVED_PORTS:
        candidates.append((source_port, OBSERVED_PORTS[source_port]))

    # One observation per packet, even if both ports are noteworthy.
    if not candidates:
        return

    # Prefer the destination service where possible.
    observed_port, service = candidates[0]

    write_observation(
        service,
        source,
        destination,
        source_port,
        destination_port,
        observed_port,
    )


# -------------------- PACKET CALLBACK --------------------

def packet_callback(packet):
    """Update counters and print a concise summary for each packet."""
    stats["Total"] += 1

    protocol = identify_protocol(packet)
    stats[protocol] += 1

    source, destination = get_addresses(packet)
    source_port, destination_port = get_ports(packet)
    service = identify_service(packet)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(
        f"{timestamp} | "
        f"{source:<39} -> {destination:<39} | "
        f"{protocol:<5} | {service:<25} | "
        f"{str(source_port):<6} -> {str(destination_port):<6} | "
        f"{len(packet)} bytes"
    )

    check_port_observation(
        packet,
        source,
        destination,
        source_port,
        destination_port,
    )


# -------------------- USER INTERFACE --------------------

def choose_filter():
    """Prompt for a predefined capture filter."""
    print("\nSelect a traffic filter:")

    for key, (description, _) in FILTERS.items():
        print(f"  {key}. {description}")

    while True:
        choice = input("Enter a number (1-7): ").strip()

        if choice in FILTERS:
            return FILTERS[choice]

        print("Invalid choice. Please enter a number from 1 to 7.")


def print_summary():
    """Print totals collected during this capture session."""
    print("\n" + "=" * 50)
    print("PACKET CAPTURE SUMMARY")
    print("=" * 50)
    print(f"Total packets        : {stats['Total']}")
    print(f"TCP                  : {stats['TCP']}")
    print(f"UDP                  : {stats['UDP']}")
    print(f"ICMP                 : {stats['ICMP']}")
    print(f"ICMPv6               : {stats['ICMPv6']}")
    print(f"ARP                  : {stats['ARP']}")
    print(f"Other                : {stats['Other']}")
    print(f"Port observations    : {stats['Alerts']}")
    print(f"Duplicate events held: {stats['Suppressed']}")
    print("=" * 50)


def main():
    print("=" * 90)
    print("CodeAlpha - Network Sniffer")
    print("Live packet capture | IPv4/IPv6 | Port observations")
    print("=" * 90)
    print(f"Interface: {INTERFACE}")
    print(f"Observation log: {LOG_FILE.resolve()}")
    print("Press Ctrl+C to stop the capture.")

    description, capture_filter = choose_filter()
    print(f"\nSelected filter: {description}")

    if capture_filter:
        print(f"BPF filter: {capture_filter}")
    else:
        print("BPF filter: none (all traffic)")

    print("\nCapture starting...\n")

    sniff(
        iface=INTERFACE,
        filter=capture_filter,
        prn=packet_callback,
        store=False,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"\n[ERROR] Packet capture could not continue: {exc}")
        print(
            "Check the interface name, Npcap installation, capture "
            "permissions, and selected filter."
        )
    except Exception as exc:
        print(f"\n[ERROR] Unexpected error: {type(exc).__name__}: {exc}")
        print("Review your Python, Scapy, and Npcap setup.")
    finally:
        print_summary()
