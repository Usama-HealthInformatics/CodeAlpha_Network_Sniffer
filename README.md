# CodeAlpha Cybersecurity Internship - Task 1

## Basic Network Sniffer and Security Monitor



### Overview

A Python network monitoring tool developed for the CodeAlpha cybersecurity internship task. It captures packets from a selected network interface, displays network metadata, identifies common services using port-based heuristics, tracks traffic statistics, and supports basic security-event detection.



### Features

- Live packet capture using Scapy

- IPv4 and IPv6 address display

- TCP, UDP, ICMP, and ARP packet classification

- Source and destination port display

- Basic service identification

- Packet capture statistics

- Traffic filtering in earlier versions

- CSV packet metadata logging in V5

- Port-based security monitoring for FTP, Telnet, SMB, and RDP

- Security-event logging in V7 and V8



### Technologies

- Python 3.14

- Scapy

- Npcap

- Windows PowerShell

- CSV and text-based logging



### Requirements

- Windows 10 or Windows 11

- Python 3.14

- Scapy

- Npcap

- Permission to capture traffic on the selected interface



### Installation

Install Scapy:



```powershell

py -3.14 -m pip install scapy

```



### Configuration

Open `network\_sniffer.py` and check that the `INTERFACE` setting matches your network adapter.



The current configuration uses:



`Intel(R) Wi-Fi 6E AX211 160MHz`



Change it if your adapter name is different.



### Usage

From the project directory, run:



```powershell

py -3.14 network\_sniffer.py

```



Press `Ctrl+C` to stop the capture and display the summary.



### Security Monitoring

The current detector checks ports associated with:



| Service | Port | Severity |

|---|---:|---|

| FTP | 21 | Medium |

| Telnet | 23 | High |

| SMB | 445 | Medium |

| RDP | 3389 | Medium |



These are basic port-based indicators. A matching packet does not automatically indicate an attack or confirm that a service is running.



### Testing

The tool was tested on Windows 11 with Scapy and Npcap. Successful runs captured live TCP, UDP, IPv6, HTTPS/TLS, and QUIC-related traffic and displayed packet statistics.



Capture counts and security alerts vary by session. A session with zero alerts means no packets matched the implemented alert conditions during that capture; it does not prove that the network is threat-free.



### Limitations

- Service identification relies on port numbers rather than deep protocol inspection.

- Encrypted application payloads are not decrypted.

- Port-based rules can produce false positives and false negatives.

- This project is a learning tool, not a replacement for a production IDS or SIEM.

- The current detector implements only a small set of security rules.



### Responsible Use

Capture traffic only on systems and networks you own or are explicitly authorized to monitor. Review logs before publishing and remove sensitive addresses, hostnames, and other private information.



### Learning Outcomes

- Practical packet capture with Scapy

- Understanding network protocols and ports

- Working with IPv4 and IPv6 traffic

- Traffic statistics and CSV logging

- Basic security detection and event logging

- Documenting a cybersecurity project



### Future Improvements

- Automated tests for detection rules

- Improved connection-state and traffic-direction tracking

- Structured event logging

- Better error handling

- Synthetic packet tests and screenshots

- Optional visualization dashboard


