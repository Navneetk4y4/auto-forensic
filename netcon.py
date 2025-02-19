import psutil
import socket
import os
from datetime import datetime
import platform
import ctypes


COLUMNS = {
    'proto': 10,
    'local': 40,
    'remote': 23,
    'status': 20,
    'pid': 8,
    'admin': 5,  
    'process': 22,  
    'path': 75     
}

def get_process_info(pid):
    """Get process details including admin privileges (cross-platform)"""
    try:
        process = psutil.Process(pid)
        exe_path = process.exe()
        name = os.path.basename(exe_path) if exe_path else process.name()
        is_admin = False

        try:
            if platform.system() == 'Windows':
                # Check if the current context is running with admin privileges
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # Check the process owner; flag as admin if the owner is "root"
                username = process.username()
                is_admin = (username == "root")
        except (psutil.AccessDenied, AttributeError):
            pass

        return name, exe_path or "N/A", is_admin
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "N/A", "N/A", False

def generate_table(connections):
    """Generate formatted table for network connections"""
    table = []
    header = (
        f"{'Proto':<{COLUMNS['proto']}} "
        f"{'Local Address':<{COLUMNS['local']}} "
        f"{'Remote Address':<{COLUMNS['remote']}} "
        f"{'Status':<{COLUMNS['status']}} "
        f"{'PID':<{COLUMNS['pid']}} "
        f"{'Admin':<{COLUMNS['admin']}} "  
        f"{'Process Name':<{COLUMNS['process']}} "
        f"{'Process Path':<{COLUMNS['path']}}"
    )
    separator = "-" * (sum(COLUMNS.values()) + (len(COLUMNS) - 1))

    table.append(header)
    table.append(separator)

    for conn in connections:
        admin_flag = 'Y' if conn['is_admin'] else 'N'
        line = (
            f"{conn['proto']:<{COLUMNS['proto']}} "
            f"{conn['local']:<{COLUMNS['local']}} "
            f"{conn['remote']:<{COLUMNS['remote']}} "
            f"{conn['status']:<{COLUMNS['status']}} "
            f"{str(conn['pid']):<{COLUMNS['pid']}} "
            f"{admin_flag:<{COLUMNS['admin']}} "  
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
        print(f"Retrieved {len(connections)} connections") 
    except RuntimeError as e:
        print(f"Error retrieving connections: {str(e)}")
        if platform.system() == 'Darwin':
            print("On macOS, try: sudo python3 network_analyzer.py")
        elif platform.system() == 'Windows':
            print("On Windows, try running as Administrator")
        return []

    processed_connections = []
    for conn in connections:
        try:
            # Determine protocol type
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

def main():
    # Display note on how to run with proper privileges
    if platform.system() == 'Darwin':
        print("Note: On macOS, you might need to:")
        print("1. Grant Full Disk Access to your terminal")
        print("2. Run with: sudo python3 netcon.py\n")
    elif platform.system() == 'Windows':
        print("Note: Run as Administrator for full visibility\n")

    processed_connections = dump_network_connections()

    if not processed_connections:
        print("No active network connections found.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"network_dump_{timestamp}.txt"

    table_lines = generate_table(processed_connections)
    with open(filename, "w") as f:
        f.write(f"Network Connections - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("\n".join(table_lines))

    print(f"Network report saved to {filename}")

if __name__ == "__main__":
    main()
