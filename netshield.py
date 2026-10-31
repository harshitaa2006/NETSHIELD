import subprocess
import re
import time
import sqlite3
import sys
from datetime import datetime


# ============================================================
# NETSHIELD CONFIGURATION
# ============================================================

DB_NAME = "netshield.db"

# Windows victim network interface
INTERFACE_INDEX = 9
INTERFACE_NAME = "Ethernet"

# How often NetShield checks the ARP table
CHECK_INTERVAL = 2

# Risk score required for automatic prevention
RESPONSE_THRESHOLD = 80


# ============================================================
# DATABASE SETUP
# ============================================================

def init_database():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Trusted IP -> MAC mappings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS baseline (
            ip_address TEXT PRIMARY KEY,
            mac_address TEXT NOT NULL,
            created_at TEXT
        )
    """)

    # Security incidents
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            trusted_mac TEXT,
            detected_mac TEXT,
            risk_score INTEGER,
            severity TEXT,
            reason TEXT,
            action TEXT
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# READ WINDOWS ARP TABLE
# ============================================================

def get_arp_table():

    result = subprocess.run(
        ["arp", "-a"],
        capture_output=True,
        text=True
    )

    arp_table = {}

    for line in result.stdout.splitlines():

        match = re.search(
            r"(\d+\.\d+\.\d+\.\d+)\s+"
            r"([0-9a-fA-F-]{17})\s+"
            r"(\w+)",
            line
        )

        if not match:
            continue

        ip = match.group(1)
        mac = match.group(2).lower()
        entry_type = match.group(3).lower()

        # Ignore broadcast / multicast addresses
        if (
            ip.startswith("224.")
            or ip.startswith("239.")
            or ip == "255.255.255.255"
        ):
            continue

        arp_table[ip] = {
            "mac": mac,
            "type": entry_type
        }

    return arp_table


# ============================================================
# CREATE BASELINE
# ============================================================

def create_baseline():

    print("\n")
    print("=" * 70)
    print("                 NETSHIELD INITIALIZATION")
    print("=" * 70)

    print("\n[!] No trusted baseline found.")
    print("[!] Capturing current clean ARP mappings...")

    arp_table = get_arp_table()

    if not arp_table:

        print("\n[ERROR] No ARP mappings found.")
        print("[ERROR] Baseline could not be created.")

        return False

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM baseline")

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    count = 0

    for ip, data in arp_table.items():

        mac = data["mac"]

        cursor.execute("""
            INSERT INTO baseline
            (
                ip_address,
                mac_address,
                created_at
            )
            VALUES (?, ?, ?)
        """, (
            ip,
            mac,
            timestamp
        ))

        print(
            f"[BASELINE] {ip} -> {mac}"
        )

        count += 1

    conn.commit()
    conn.close()

    print(
        f"\n[✓] Trusted baseline created "
        f"with {count} mappings."
    )

    return True


# ============================================================
# RESET BASELINE
# ============================================================

def reset_baseline():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM baseline"
    )

    conn.commit()
    conn.close()

    print(
        "[✓] Existing baseline removed."
    )

    print(
        "[+] Creating new trusted baseline..."
    )

    return create_baseline()


# ============================================================
# LOAD BASELINE
# ============================================================

def load_baseline():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ip_address, mac_address
        FROM baseline
    """)

    rows = cursor.fetchall()

    conn.close()

    baseline = {}

    for ip, mac in rows:

        baseline[ip] = mac.lower()

    return baseline


# ============================================================
# LOG INCIDENT
# ============================================================

def log_incident(
    ip,
    trusted_mac,
    detected_mac,
    risk_score,
    severity,
    reason,
    action
):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO incidents
        (
            timestamp,
            ip_address,
            trusted_mac,
            detected_mac,
            risk_score,
            severity,
            reason,
            action
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        ip,
        trusted_mac,
        detected_mac,
        risk_score,
        severity,
        reason,
        action
    ))

    conn.commit()
    conn.close()


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_risk(
    trusted_mac,
    detected_mac
):

    score = 0
    indicators = []

    if detected_mac != trusted_mac:

        score += 80

        indicators.append(
            "IP-to-MAC mapping changed"
        )

        indicators.append(
            "Observed MAC differs from trusted baseline"
        )

    if score >= 80:

        severity = "CRITICAL"

    elif score >= 50:

        severity = "SUSPICIOUS"

    else:

        severity = "LOW"

    return score, severity, indicators


# ============================================================
# DISPLAY ALERT
# ============================================================

def display_alert(
    ip,
    trusted_mac,
    detected_mac,
    risk_score,
    severity,
    indicators
):

    print("\n")
    print("=" * 70)
    print("                    NETSHIELD ALERT")
    print("=" * 70)

    print(
        f"Time         : "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    print(
        f"IP Address   : {ip}"
    )

    print(
        f"Trusted MAC  : {trusted_mac}"
    )

    print(
        f"Detected MAC : {detected_mac}"
    )

    print(
        f"Risk Score   : {risk_score}/100"
    )

    print(
        f"Severity     : {severity}"
    )

    print("\nIndicators:")

    for indicator in indicators:

        print(
            f"  • {indicator}"
        )

    print("=" * 70)


# ============================================================
# PREVENTION
# ============================================================

def restore_mapping(
    ip,
    trusted_mac
):

    print("\n")
    print("                 PREVENTION RESPONSE")
    print("-" * 70)

    # --------------------------------------------------------
    # STEP 1
    # Remove suspicious ARP entry
    # --------------------------------------------------------

    print(
        f"[RESPONSE] Removing suspicious mapping for {ip}..."
    )

    delete_result = subprocess.run(
        [
            "arp",
            "-d",
            ip
        ],
        capture_output=True,
        text=True
    )

    if delete_result.returncode == 0:

        print(
            "[✓] Suspicious mapping removed."
        )

    else:

        print(
            "[!] Dynamic ARP entry could not be removed."
        )

    # --------------------------------------------------------
    # STEP 2
    # Restore trusted mapping temporarily
    # --------------------------------------------------------

    print(
        "[RESPONSE] Restoring trusted mapping from baseline..."
    )

    add_result = subprocess.run(
        [
            "netsh",
            "interface",
            "ipv4",
            "set",
            "neighbors",
            f"interface={INTERFACE_INDEX}",
            f"address={ip}",
            f"neighbor={trusted_mac}",
            "store=active"
        ],
        capture_output=True,
        text=True
    )

    if add_result.returncode != 0:

        print(
            "[ERROR] Trusted mapping could not be restored."
        )

        if add_result.stdout:
            print(add_result.stdout.strip())

        if add_result.stderr:
            print(add_result.stderr.strip())

        return "PREVENTION FAILED"

    print(
        "[✓] Trusted mapping restored."
    )

    # --------------------------------------------------------
    # STEP 3
    # Verify trusted mapping
    # --------------------------------------------------------

    print(
        "[VERIFY] Checking trusted mapping..."
    )

    time.sleep(1)

    verify_result = subprocess.run(
        [
            "netsh",
            "interface",
            "ipv4",
            "show",
            "neighbors"
        ],
        capture_output=True,
        text=True
    )

    output = verify_result.stdout.lower()

    trusted_verified = (
        ip.lower() in output
        and trusted_mac.lower() in output
    )

    if not trusted_verified:

        print(
            "[ERROR] Trusted mapping could not be verified."
        )

        return "PREVENTION FAILED"

    print(
        f"[✓] Verified: {ip} -> {trusted_mac}"
    )

    print(
        "[✓] AUTOMATIC PREVENTION SUCCESSFUL"
    )

    # --------------------------------------------------------
    # STEP 4
    # Remove temporary static protection
    # --------------------------------------------------------

    print(
        "[RESET] Releasing temporary static ARP protection..."
    )

    reset_result = subprocess.run(
        [
            "netsh",
            "interface",
            "ipv4",
            "delete",
            "neighbors",
            f"name={INTERFACE_INDEX}",
            f"address={ip}"
        ],
        capture_output=True,
        text=True
    )

    if reset_result.returncode == 0:

        print(
            "[✓] Temporary static mapping removed."
        )

    else:

        print(
            "[!] Could not release temporary static mapping."
        )

        if reset_result.stdout:
            print(reset_result.stdout.strip())

        if reset_result.stderr:
            print(reset_result.stderr.strip())

        return "PREVENTION SUCCESSFUL - RESET FAILED"

    # --------------------------------------------------------
    # STEP 5
    # Re-establish normal dynamic ARP state
    # --------------------------------------------------------

    print(
        "[RESET] Re-establishing normal dynamic ARP state..."
    )

    time.sleep(1)

    # Ping the legitimate IP.
    #
    # This causes Windows to perform normal ARP
    # resolution again if the entry is missing.
    subprocess.run(
        [
            "ping",
            "-n",
            "1",
            "-w",
            "1000",
            ip
        ],
        capture_output=True,
        text=True
    )

    time.sleep(1)

    # --------------------------------------------------------
    # STEP 6
    # Verify dynamic mapping
    # --------------------------------------------------------

    arp_table = get_arp_table()

    if ip in arp_table:

        current_mac = arp_table[ip]["mac"]

        if current_mac == trusted_mac:

            print(
                f"[✓] Dynamic mapping restored: "
                f"{ip} -> {trusted_mac}"
            )

            print(
                "[✓] NetShield ready for the next attack."
            )

        else:

            print(
                f"[!] {ip} currently resolves to "
                f"{current_mac}"
            )

            print(
                f"[!] Expected trusted MAC: "
                f"{trusted_mac}"
            )

    else:

        print(
            "[!] Legitimate mapping is not yet "
            "present in the ARP cache."
        )

        print(
            "[!] NetShield will continue monitoring."
        )

    return "AUTOMATIC PREVENTION SUCCESSFUL"


# ============================================================
# MONITORING ENGINE
# ============================================================

def monitor():

    baseline = load_baseline()

    if not baseline:

        print(
            "\n[ERROR] No trusted baseline available."
        )

        return

    print("\n")
    print("=" * 70)
    print("                    NETSHIELD")
    print("        ARP INTRUSION DETECTION & PREVENTION")
    print("=" * 70)

    print(
        f"\n[+] Trusted mappings loaded : "
        f"{len(baseline)}"
    )

    print(
        f"[+] Interface               : "
        f"{INTERFACE_NAME} ({INTERFACE_INDEX})"
    )

    print(
        f"[+] Monitoring interval     : "
        f"{CHECK_INTERVAL} seconds"
    )

    print(
        "\n[✓] NETSHIELD IS ACTIVE"
    )

    print(
        "[+] Monitoring IP-to-MAC mappings..."
    )

    print(
        "[+] Press CTRL+C to stop.\n"
    )

    # --------------------------------------------------------
    # Remember which suspicious MAC has already generated
    # an alert.
    #
    # When the mapping returns to the trusted MAC,
    # this entry is removed.
    #
    # Therefore the SAME attack can trigger another alert.
    # --------------------------------------------------------

    last_alerted_mac = {}

    try:

        while True:

            current_arp = get_arp_table()

            # ------------------------------------------------
            # Check EVERY trusted mapping
            # ------------------------------------------------

            for ip, trusted_mac in baseline.items():

                # ------------------------------------------------
                # IP is currently not in ARP cache
                # ------------------------------------------------

                if ip not in current_arp:

                    continue

                detected_mac = current_arp[ip]["mac"]

                # ------------------------------------------------
                # NORMAL / TRUSTED
                # ------------------------------------------------

                if detected_mac == trusted_mac:

                    # Reset alert state.
                    #
                    # This is what allows the same attacker MAC
                    # to trigger another alert later.
                    last_alerted_mac.pop(
                        ip,
                        None
                    )

                    continue

                # ------------------------------------------------
                # SUSPICIOUS
                # ------------------------------------------------

                if last_alerted_mac.get(ip) == detected_mac:

                    # Same suspicious mapping is still present.
                    # Do not spam the terminal.
                    continue

                # ------------------------------------------------
                # New anomaly detected
                # ------------------------------------------------

                last_alerted_mac[ip] = detected_mac

                # ------------------------------------------------
                # Calculate risk
                # ------------------------------------------------

                risk_score, severity, indicators = \
                    calculate_risk(
                        trusted_mac,
                        detected_mac
                    )

                # ------------------------------------------------
                # Display alert
                # ------------------------------------------------

                display_alert(
                    ip,
                    trusted_mac,
                    detected_mac,
                    risk_score,
                    severity,
                    indicators
                )

                action = (
                    "INVESTIGATION REQUIRED"
                )

                # ------------------------------------------------
                # Automatic prevention
                # ------------------------------------------------

                if risk_score >= RESPONSE_THRESHOLD:

                    action = restore_mapping(
                        ip,
                        trusted_mac
                    )

                # ------------------------------------------------
                # Log incident
                # ------------------------------------------------

                reason = "; ".join(
                    indicators
                )

                log_incident(
                    ip,
                    trusted_mac,
                    detected_mac,
                    risk_score,
                    severity,
                    reason,
                    action
                )

                print(
                    "\n[LOG] Security incident recorded."
                )

                print(
                    "[MONITOR] Continuing protection...\n"
                )

            time.sleep(
                CHECK_INTERVAL
            )

    except KeyboardInterrupt:

        print("\n")
        print("=" * 70)
        print(
            "[+] NetShield monitoring stopped."
        )
        print("=" * 70)


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print("\n")
    print("=" * 70)
    print("                    NETSHIELD")
    print("             SECURITY MONITORING SYSTEM")
    print("=" * 70)

    # --------------------------------------------------------
    # Initialize database
    # --------------------------------------------------------

    init_database()

    # --------------------------------------------------------
    # Optional baseline reset
    # --------------------------------------------------------

    if (
        len(sys.argv) > 1
        and sys.argv[1] == "--reset-baseline"
    ):

        print(
            "\n[+] Baseline reset requested."
        )

        success = reset_baseline()

        if not success:

            print(
                "[ERROR] Could not create baseline."
            )

            return

    # --------------------------------------------------------
    # Normal startup
    # --------------------------------------------------------

    else:

        baseline = load_baseline()

        if not baseline:

            print(
                "\n[+] First-time setup detected."
            )

            success = create_baseline()

            if not success:

                return

        else:

            print(
                "\n[✓] Existing trusted baseline loaded."
            )

            print(
                f"[+] {len(baseline)} trusted mappings available."
            )

    # --------------------------------------------------------
    # Start monitoring automatically
    # --------------------------------------------------------

    monitor()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()