import psutil
import socket
import os
from datetime import datetime
import hashlib
import requests
import time
import ctypes
import platform


COLUMNS = {
    'proto': 10,
    'local': 40,
    'remote': 23,
    'status': 20,
    'pid': 8,
    'process': 27,
    'path': 75
}
VIRUSTOTAL_API_KEY = "4f3d391862ceeabbd55f72fd9ceca94a116b5d8f7767b2a126a730ad3bc7384d"  # Replace with your actual API key


def get_process_info(pid):
    """Get process details including admin privileges (cross-platform)"""
    try:
        process = psutil.Process(pid)
        exe_path = process.exe()
        name = os.path.basename(exe_path) if exe_path else process.name()
        is_admin = False

        try:
            if platform.system() == 'Windows':
                # Windows admin check
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # Unix/Linux/Mac admin check
                is_admin = os.geteuid() == 0
        except (psutil.AccessDenied, AttributeError):
            pass

        return name, exe_path or "N/A", is_admin
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "N/A", "N/A", False


def generate_table(connections, is_admin_section=False):
    """Generate formatted table for network connections"""
    table = []
    header = (
        f"{'Proto':<{COLUMNS['proto']}} "
        f"{'Local Address':<{COLUMNS['local']}} "
        f"{'Remote Address':<{COLUMNS['remote']}} "
        f"{'Status':<{COLUMNS['status']}} "
        f"{'PID':<{COLUMNS['pid']}} "
        f"{'Process Name':<{COLUMNS['process']}} "
        f"{'Process Path':<{COLUMNS['path']}}"
    )
    
    
    separator = "-" * (sum(COLUMNS.values()) + (len(COLUMNS) - 1))

    if is_admin_section:
        table.append("\nADMIN/ROOT PROCESSES:")
    else:
        table.append("\nSTANDARD PROCESSES:")

    table.append(header)
    table.append(separator)

    for conn in connections:
        line = (
            f"{conn['proto']:<{COLUMNS['proto']}} "
            f"{conn['local']:<{COLUMNS['local']}} "
            f"{conn['remote']:<{COLUMNS['remote']}} "
            f"{conn['status']:<{COLUMNS['status']}} "
            f"{str(conn['pid']):<{COLUMNS['pid']}} "
            f"{conn['pname'][:COLUMNS['process']]:<{COLUMNS['process']}} "
            f"{str(conn['ppath'])[:COLUMNS['path']]:<{COLUMNS['path']}}"
        )
        table.extend([line, separator])

    if connections:
        table.pop()

    return table


def dump_network_connections():
    """Generate network connection report"""
    try:
        connections = psutil.net_connections(kind='inet')
    except RuntimeError as e:
        print(f"Error retrieving connections: {str(e)}")
        if platform.system() == 'Darwin':
            print("On macOS, try: sudo python3 script.py")
        elif platform.system() == 'Windows':
            print("On Windows, try running as Administrator")
        return []

    processed_connections = []
    for conn in connections:
        try:
            # Windows-specific UDP handling
            if platform.system() == 'Windows':
                proto = "UDP" if conn.type == socket.SOCK_DGRAM and conn.laddr else "TCP"
            else:
                proto = "UDP" if conn.type == socket.SOCK_DGRAM else "TCP"

            status = "" if proto == "UDP" else conn.status
            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "*.*.*.*:*"
            pname, ppath, is_admin = get_process_info(conn.pid)

            processed_connections.append({
                'proto': proto,
                'local': local,
                'remote': remote,
                'status': status,
                'pid': conn.pid,
                'pname': pname,
                'ppath': ppath,
                'is_admin': is_admin
            })
        except Exception as e:
            print(f"Error processing connection: {str(e)}")
            continue

    return processed_connections


def generate_md5(file_path):
    """Generate MD5 hash for a file"""
    try:
        if not os.path.isfile(file_path):
            return None
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        return f"Error: {str(e)}"


def dump_process_hashes():
    """Generate MD5 hashes for all processes"""
    process_paths = set()
    for proc in psutil.process_iter(['pid', 'exe']):
        try:
            if proc.info['exe']:
                # Normalize path for Windows
                path = os.path.normpath(proc.info['exe'])
                process_paths.add(path)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    hash_filename = f"prochash{timestamp}.txt"
    hashes = []

    for path in process_paths:
        md5_hash = generate_md5(path)
        if md5_hash and not md5_hash.startswith("Error"):
            hashes.append(f"{md5_hash}  {path}")

    if hashes:
        with open(hash_filename, "w") as f:
            f.write("\n".join(hashes))
        print(f"Process hashes dumped to {hash_filename}")
        return hash_filename
    return None


def check_virustotal(hash_filename):
    """Check hashes against VirusTotal"""
    if not os.path.exists(hash_filename):
        return

    output_filename = f"vt_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(hash_filename) as f:
        lines = [line.strip() for line in f.readlines()]

    with open(output_filename, "w") as out:
        out.write(f"Source Hash File: {hash_filename}\n\n")
        out.write(f"{'Hash':<35}{'Malicious':<11}{'Detection':<11}{'Process Name':<30}{'Executable Path'}\n")
        out.write("=" * 110 + "\n")  # Increased separator length

        for line in lines:
            if '  ' not in line:
                continue
            md5_hash, path = line.split('  ', 1)

            # VirusTotal API call
            url = f"https://www.virustotal.com/api/v3/files/{md5_hash}"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}

            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get('data', {}).get('attributes', {})
                    meaningful_name = stats.get('meaningful_name', 'N/A')
                    analysis_stats = stats.get('last_analysis_stats', {})
                    malicious = analysis_stats.get('malicious', 0)
                    total = analysis_stats.get('total', 0)
                    detection = f"{malicious}/{total}"

                    out.write(f"{md5_hash:<35}{malicious:<11}{detection:<11}{meaningful_name[:30]:<30}{path}\n")
                else:
                    out.write(f"{md5_hash:<35}Error       API Error: {response.status_code}{'N/A':<30}{path}\n")
            except Exception as e:
                out.write(f"{md5_hash:<35}Error       {str(e)[:11]:<11}{'N/A':<30}{path}\n")


    print(f"\nVirusTotal results saved to {output_filename}")

def main():
    """Main execution flow"""
    if platform.system() == 'Darwin':
        print("Note: On macOS, you might need to:")
        print("1. Grant Full Disk Access to your terminal in System Preferences")
        print("2. Run with: sudo python3 script.py\n")
    elif platform.system() == 'Windows':
        print("Note: On Windows, run as Administrator for full process visibility\n")

    # Generate network connection report
    processed_connections = dump_network_connections()

    if processed_connections:
        admin_conns = [c for c in processed_connections if c['is_admin']]
        normal_conns = [c for c in processed_connections if not c['is_admin']]

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        network_filename = f"network_dump_{timestamp}.txt"

        with open(network_filename, "w") as f:
            f.write(f"Network Connections Dump - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("\n".join(generate_table(normal_conns)))
            f.write("\n" * 3)
            f.write("\n".join(generate_table(admin_conns, is_admin_section=True)))

        print(f"Network connections dumped to {network_filename}")

    # Generate process hashes and check with VirusTotal
    hash_file = dump_process_hashes()
    if hash_file:
        check_virustotal(hash_file)


if __name__ == "__main__":
    main()