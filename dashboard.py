import streamlit as st
import sqlite3
import subprocess
import re
from datetime import datetime

# ============================================================
# NETSHIELD DASHBOARD
# ============================================================

DB_NAME = "netshield.db"

TRUSTED_MAPPINGS = {
    "192.168.56.1": "0a-00-27-00-00-12"
}

# ============================================================
# PAGE SETTINGS
# ============================================================

st.set_page_config(
    page_title="NetShield",
    page_icon="🛡️",
    layout="wide"
)

# ============================================================
# FUNCTIONS
# ============================================================

def get_arp_table():

    result = subprocess.run(
        ["arp", "-a"],
        capture_output=True,
        text=True
    )

    arp_data = {}

    for line in result.stdout.splitlines():

        match = re.search(
            r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)",
            line
        )

        if match:

            ip = match.group(1)
            mac = match.group(2).lower()

            arp_data[ip] = mac

    return arp_data


def get_incidents():

    try:

        connection = sqlite3.connect(DB_NAME)

        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                timestamp,
                ip_address,
                trusted_mac,
                detected_mac,
                risk_score,
                severity,
                reason,
                action
            FROM incidents
            ORDER BY id DESC
        """)

        incidents = cursor.fetchall()

        connection.close()

        return incidents

    except sqlite3.Error:

        return []


def check_mappings():

    arp_table = get_arp_table()

    results = []

    for ip, trusted_mac in TRUSTED_MAPPINGS.items():

        current_mac = arp_table.get(ip)

        if current_mac is None:

            status = "⚠️ Not Found"

        elif current_mac.lower() == trusted_mac.lower():

            status = "✅ Trusted"

        else:

            status = "🚨 Anomaly"

        results.append({
            "ip": ip,
            "trusted_mac": trusted_mac,
            "current_mac": current_mac
                if current_mac
                else "Not present",
            "status": status
        })

    return results


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ NETSHIELD")

st.subheader("ARP Anomaly Detection & Response System")

st.write(
    "Real-time monitoring of trusted IP-to-MAC mappings, "
    "risk assessment, automated response and incident logging."
)

# ============================================================
# MANUAL REFRESH
# ============================================================

refresh_col1, refresh_col2 = st.columns([1, 5])

with refresh_col1:

    if st.button(
        "🔄 Refresh Dashboard",
        use_container_width=True
    ):

        st.rerun()

with refresh_col2:

    st.caption(
        "Click Refresh Dashboard to check the latest "
        "network and incident status."
    )

st.divider()


# ============================================================
# CURRENT STATUS
# ============================================================

mapping_data = check_mappings()

active_anomalies = 0

for item in mapping_data:

    if item["status"] == "🚨 Anomaly":

        active_anomalies += 1


if active_anomalies == 0:

    system_status = "🟢 PROTECTED"

else:

    system_status = "🔴 ANOMALY DETECTED"


# ============================================================
# STATUS CARDS
# ============================================================

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "System Status",
        system_status
    )

with col2:

    st.metric(
        "Protected Assets",
        len(TRUSTED_MAPPINGS)
    )

with col3:

    st.metric(
        "Active Anomalies",
        active_anomalies
    )

with col4:

    st.metric(
        "Last Dashboard Scan",
        datetime.now().strftime("%H:%M:%S")
    )


st.divider()


# ============================================================
# TRUSTED NETWORK MAPPINGS
# ============================================================

st.header("🔐 Trusted Network Mappings")

for item in mapping_data:

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.write("**IP Address**")
        st.code(item["ip"])

    with col2:

        st.write("**Trusted MAC**")
        st.code(item["trusted_mac"])

    with col3:

        st.write("**Current MAC**")
        st.code(item["current_mac"])

    with col4:

        st.write("**Status**")

        if item["status"] == "🚨 Anomaly":

            st.error(item["status"])

        elif item["status"] == "✅ Trusted":

            st.success(item["status"])

        else:

            st.warning(item["status"])


st.divider()


# ============================================================
# LATEST SECURITY INCIDENT
# ============================================================

st.header("🚨 Latest Security Incident")

incidents = get_incidents()

if len(incidents) == 0:

    st.info("No security incidents recorded yet.")

else:

    latest = incidents[0]

    timestamp = latest[0]
    ip_address = latest[1]
    trusted_mac = latest[2]
    detected_mac = latest[3]
    risk_score = latest[4]
    severity = latest[5]
    reason = latest[6]
    action = latest[7]

    col1, col2, col3 = st.columns(3)

    with col1:

        st.write("**Time**")
        st.write(timestamp)

        st.write("**IP Address**")
        st.code(ip_address)

    with col2:

        st.write("**Trusted MAC**")
        st.code(trusted_mac)

        st.write("**Detected MAC**")
        st.code(detected_mac)

    with col3:

        st.write("**Risk Score**")

        st.metric(
            "Risk",
            f"{risk_score}/100"
        )

        st.write("**Severity**")

        if severity == "CRITICAL":

            st.error(severity)

        elif severity == "SUSPICIOUS":

            st.warning(severity)

        else:

            st.info(severity)

    st.write("**Detection Indicators**")
    st.write(reason)

    st.write("**Response Action**")
    st.success(action)


st.divider()


# ============================================================
# RISK ASSESSMENT
# ============================================================

st.header("📊 Risk Assessment")

st.write(
    "NetShield uses a rule-based risk score to assess "
    "ARP mapping anomalies."
)

col1, col2, col3 = st.columns(3)

with col1:

    st.metric(
        "Trusted IP changed MAC",
        "+60"
    )

with col2:

    st.metric(
        "Unexpected MAC mismatch",
        "+20"
    )

with col3:

    st.metric(
        "Maximum Risk",
        "100"
    )

st.caption(
    "Risk ≥ 80 → CRITICAL | "
    "Risk ≥ 50 → SUSPICIOUS | "
    "Below 50 → LOW"
)


st.divider()


# ============================================================
# INCIDENT HISTORY
# ============================================================

st.header("📜 Incident History")

if len(incidents) == 0:

    st.info("No incidents recorded.")

else:

    for incident in incidents:

        timestamp = incident[0]
        ip_address = incident[1]
        trusted_mac = incident[2]
        detected_mac = incident[3]
        risk_score = incident[4]
        severity = incident[5]
        reason = incident[6]
        action = incident[7]

        with st.expander(
            f"{timestamp} | {ip_address} | "
            f"{severity} | Risk {risk_score}/100"
        ):

            st.write(
                "**IP Address:**",
                ip_address
            )

            st.write(
                "**Trusted MAC:**",
                trusted_mac
            )

            st.write(
                "**Detected MAC:**",
                detected_mac
            )

            st.write(
                "**Risk Score:**",
                f"{risk_score}/100"
            )

            st.write(
                "**Severity:**",
                severity
            )

            st.write(
                "**Detection Indicators:**",
                reason
            )

            st.write(
                "**Response:**",
                action
            )


st.divider()


# ============================================================
# ABOUT NETSHIELD
# ============================================================

st.header("ℹ️ About NetShield")

st.write(
    "NetShield establishes a trusted IP-to-MAC baseline "
    "and monitors the Windows ARP table for unexpected "
    "mapping changes."
)

st.write(
    "When an anomaly is detected, the system calculates "
    "a risk score, generates an alert, performs the configured "
    "response, verifies the resulting mapping and records "
    "the incident in SQLite."
)

st.caption(
    "Controlled laboratory prototype — Host-only VirtualBox network"
)