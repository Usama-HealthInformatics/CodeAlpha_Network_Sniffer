# CodeAlpha Cybersecurity Internship — Task 1

## Basic Network Sniffer and Security Monitor

### Overview
This project is a Python-based network sniffer developed as part of my CodeAlpha Cybersecurity Internship. It uses Scapy to capture network packets and inspect network traffic metadata for basic security monitoring.

### Features
- Capture live network packets.
- Display packet metadata, including source and destination addresses.
- Identify common protocols and services.
- Display packet statistics.
- Apply traffic filters, where supported by the selected version.
- Log packet metadata to CSV.
- Flag selected traffic involving services such as FTP, Telnet, SMB, and RDP.
- Record basic security events.

### Technologies
- Python
- Scapy
- Npcap
- Git and GitHub

### Requirements
- Windows, Linux, or another Scapy-supported operating system.
- Python 3.14 or another version compatible with the installed Scapy release.
- Scapy 2.8.0.
- Npcap on Windows for packet capture.
- Permission to capture traffic on the selected network interface.

### Installation
1. Install Python.
2. Install Npcap on Windows if required.
3. Clone this repository:

   ```bash
   git clone https://github.com/Usama-HealthInformatics/CodeAlpha_Network_Sniffer.git
   cd CodeAlpha_Network_Sniffer
   ```

4. Install the dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

### Usage
Run the script from a terminal with the permissions required for packet capture:

```bash
python network_sniffer.py
```

Select the available interface or traffic filter if prompted. Follow the on-screen instructions to view traffic and stop the capture.

### Security and Privacy
Use this tool only on networks and devices you own or are explicitly authorized to monitor. Packet captures may expose sensitive information, so protect logs and avoid publishing captured traffic or personal data.

### Limitations
This is an educational project, not a production-grade intrusion detection system. Port-based alerts are basic heuristics and do not prove malicious activity. Encrypted traffic generally prevents inspection of application contents.

### Future Improvements
- Add unit tests and improved error handling.
- Improve protocol identification and alert accuracy.
- Add configurable detection rules.
- Create visual summaries of packet statistics.
- Document test cases and sample results.

### Author
**Usama** — Cybersecurity learner interested in network security, SOC operations, and defensive security.

GitHub: https://github.com/Usama-HealthInformatics



## Other CodeAlpha Internship Project

### Task 2 — Phishing Awareness Training

A cybersecurity awareness project covering phishing warning signs, suspicious links, social engineering, and safe reporting practices.

- [View the project files and presentation link](https://github.com/Usama-HealthInformatics/CodeAlpha_Network_Sniffer/tree/main/Phishing-Awareness-Training)
- Deliverables: Google Slides presentation, downloadable PowerPoint file, and a 10-question quiz with an answer key.

