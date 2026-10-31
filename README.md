# IDPS-mini-project
# NetShield – ARP Intrusion Detection and Prevention System

## Team Members:
Harshita Chaudhari
Isha Harne
Meenakshi Motwani
Anandi Bhute

## Overview

NetShield is a lightweight, host-based Intrusion Detection and Prevention System (IDPS) designed to detect suspicious ARP (Address Resolution Protocol) mapping changes that may indicate ARP spoofing attacks.

It monitors trusted IP-to-MAC address mappings, identifies unexpected changes, generates security alerts, calculates a risk score, and attempts an automated response to restore the trusted mapping.

## Problem Statement

ARP spoofing is a technique in which an attacker sends forged ARP messages to associate their MAC address with the IP address of a legitimate device. This can create opportunities for Man-in-the-Middle (MITM) attacks.

NetShield aims to provide a lightweight endpoint-level mechanism to monitor ARP mappings, identify suspicious changes, and respond automatically.

## Key Features

- Trusted IP-to-MAC baseline configuration
- Continuous ARP table monitoring
- Detection of suspicious mapping changes
- Rule-based risk assessment
- Automatic response using Windows neighbor-table configuration
- Verification of the response
- Security incident logging using SQLite
- Streamlit-based monitoring dashboard

## Technologies Used

- Python
- SQLite
- Streamlit
- Windows Networking Commands (ARP and Netsh)
- Kali Linux
- Scapy
- Oracle VirtualBox

## System Architecture

The project consists of three main components:

1. **Detection and Prevention Engine (`netshield.py`):** Monitors ARP mappings, detects anomalies, calculates risk scores, performs the configured response, and logs incidents.
2. **Dashboard (`dashboard.py`):** Displays trusted mappings, current network status, detected anomalies, and incident history.
3. **Database (`netshield.db`):** Stores trusted IP-to-MAC mappings and security incident records. It is generated automatically when the application runs.

## Project Structure

```text
NetShield/
│
├── netshield.py
├── dashboard.py
├── config.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation and Setup

1. Install Python 3.9 or later.
2. Clone this repository:

```bash
git clone YOUR_REPOSITORY_URL
```

3. Navigate to the project directory:

```bash
cd NetShield
```

4. Install the required dependencies:

```bash
pip install -r requirements.txt
```

5. Configure the trusted network mappings and interface details in `config.py`.

## Running the Project

### Start the Detection and Prevention Engine

Open Command Prompt as Administrator and run:

```bash
python netshield.py
```

### Start the Dashboard

Open another terminal in the project directory and run:

```bash
python -m streamlit run dashboard.py
```

The dashboard can be refreshed to view the latest ARP status and recorded incidents.

## Testing Environment

The project was developed and tested in a controlled virtual environment using:

- Windows 11 Virtual Machine – Victim
- Kali Linux Virtual Machine – Attack Simulation
- VirtualBox Host-Only Network – Isolated communication between virtual machines

Scapy was used in the controlled lab to simulate forged ARP replies.

## Limitations

- The system monitors configured trusted IP-to-MAC mappings rather than all network traffic.
- A mapping mismatch is treated as a suspicious anomaly and does not independently prove malicious activity.
- Legitimate network changes may require updating the trusted baseline.
- The prevention mechanism is Windows-specific and requires administrator privileges.
- The dashboard requires manual refresh and does not independently run the detection engine.

## Disclaimer

NetShield is an academic security project intended for educational purposes and authorized testing in an isolated lab environment. It should only be used on networks and systems for which permission has been granted.

