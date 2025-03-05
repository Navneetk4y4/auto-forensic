import csv
import subprocess
import re
import os
import requests
from dotenv import load_dotenv
import pandas as pd

# Load API key from .env file
load_dotenv()
API_KEY = os.getenv("ABUSEIP_API_KEY")


def get_network_connections():
    """Get all network connections using netstat -ano"""
    try:
        result = subprocess.check_output(
            ['netstat', '-ano'],
            text=True,
            stderr=subprocess.STDOUT,
            shell=True
        )
        return result
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        return None


def parse_connections(netstat_output):
    """Parse netstat output for Windows"""
    connections = []
    foreign_ips = set()
    
    # List of IPs/hostnames to exclude from foreign_ips
    ignore_ips = {
        '0.0.0.0', '127.0.0.1', '::', '::1', 'localhost',
        'localhost.localdomain', '*', '255.255.255.255'
    }

    for line in netstat_output.split('\n'):
        if not line.strip() or 'Active Connections' in line:
            continue

        cleaned = re.sub(r'\s+', ' ', line).strip()
        parts = cleaned.split(' ')

        if len(parts) >= 4:
            protocol = parts[0]
            local_addr = parts[1]
            foreign_addr = parts[2]
            state = parts[3] if protocol == 'TCP' else 'N/A'
            pid = parts[4] if len(parts) > 4 else 'N/A'

            # Always add to connections list
            connections.append({
                'Protocol': protocol,
                'Local Address': local_addr,
                'Foreign Address': foreign_addr,
                'State': state,
                'PID': pid
            })

            # Extract IP from foreign address
            if foreign_addr.startswith('['):
                ip_port = foreign_addr.split(']:')
                ip = ip_port[0][1:] if len(ip_port) > 1 else foreign_addr
            else:
                ip = foreign_addr.split(':')[0]

            # Add to foreign_ips only if not in ignore list
            if ip not in ignore_ips:
                foreign_ips.add(ip)

    return connections, foreign_ips


def check_ip_abuse(ip_address):
    """Check an IP address on AbuseIPDB and return abuse details"""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90  # Check reports from last 90 days
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json().get("data", {})
        return {
            "IP Address": data.get("ipAddress"),
            "Abuse Score": data.get("abuseConfidenceScore"),
            "Total Reports": data.get("totalReports"),
            "ISP": data.get("isp"),
            "Country": data.get("countryCode"),
            "Last Reported": data.get("lastReportedAt")
        }
    else:
        return {
            "IP Address": ip_address,
            "Abuse Score": "Error",
            "Total Reports": "Error",
            "ISP": "Error",
            "Country": "Error",
            "Last Reported": "Error"
        }


def save_to_csv(data, filename, fieldnames):
    """Save data to CSV file"""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)


def main():
    # Get network connections
    output = get_network_connections()
    if not output:
        print("❌ Failed to get network connections")
        return

    # Parse connections and extract foreign IPs
    connections, foreign_ips = parse_connections(output)
    
    # Save all network connections
    save_to_csv(
        connections,
        'network_connections.csv',
        ['Protocol', 'Local Address', 'Foreign Address', 'State', 'PID']
    )
    
    # Save foreign IPs to CSV
    with open('foreign_addresses.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Foreign IP Address'])
        writer.writerows([[ip] for ip in foreign_ips])

    print("✅ Successfully created:")
    print("- network_connections.csv (all connections)")
    print("- foreign_addresses.csv (unique foreign IPs)")

    # Check each foreign IP with AbuseIPDB API
    abuse_results = []
    for ip in foreign_ips:
        abuse_results.append(check_ip_abuse(ip))

    # Save abuse report to CSV
    df = pd.DataFrame(abuse_results)
    df.to_csv("abuse_report.csv", index=False)

    print("✅ abuse_report.csv created with IP reputation details")


if __name__ == "__main__":
    main()
