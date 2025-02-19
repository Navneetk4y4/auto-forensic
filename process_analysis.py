import psutil, requests
import time
import csv
from datetime import datetime
import hashlib
import ctypes
import platform
from dotenv import load_dotenv
import os
VT_URL = "https://www.virustotal.com/api/v3/files/"
load_dotenv()  # Load environment variables from .env file
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
outputfile="process_report.csv"
new_columns = ["Malicious", "Suspicious", "Undetected", "First Seen", "Last Analysis Date", "Threat Label"]
if not API_KEY:
    raise ValueError("❌ VirusTotal API key not found in .env file!")


def get_file_hash(filepath, algo="md5"):
    try:
        hasher = hashlib.new(algo)
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (FileNotFoundError, PermissionError):
        return "FileNot Found"
def get_process_info(outputfile):
    
    
    with open(outputfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["PID", "PPID", "Name", "Executable Path", "CMD Command", "User", "Status", 
                         "Creation Time","Working Directory", "Memory Usage (MB)", "Read Count", "Write Count", "MD5"])

        for proc in psutil.process_iter(attrs=['pid','ppid','name', 'exe','cmdline', 'username','status','create_time', 'cwd','memory_info','open_files','io_counters']):

            try:
                
                pid = proc.info['pid']
                ppid=proc.info['ppid']
                name=proc.info['name']
                exe_path= proc.info['exe'] or "N/A"
                cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else "N/A"
                username = proc.info.get('username', "N/A")
                status = proc.info.get('status', "N/A")
                create_time = proc.info.get('create_time', "N/A")
                cwd = proc.info.get('cwd', "N/A")
                memory_info = proc.info['memory_info'].rss / (1024 * 1024)

               
                try:    
                        open_files = proc.open_files()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                        open_files = "Access Denied"
                io_counters = proc.info['io_counters']
                read_count = io_counters.read_count if io_counters else "N/A"
                write_count = io_counters.write_count if io_counters else "N/A"
                file_hash = get_file_hash(exe_path) if exe_path != "N/A" else "N/A"
                #check if process is running as admin (win32security) to be done later
                

                writer.writerow([pid,ppid,name, exe_path,cmdline, username,status,create_time, cwd,round(memory_info, 2), read_count, write_count, file_hash])
            except psutil.NoSuchProcess as e:
                print(f"Process no longer exists: {e}")
            except psutil.AccessDenied as e:
                print(f"Access denied to process: {e}")
            except psutil.ZombieProcess as e:
                print(f"Zombie process encountered: {e}")
            except Exception as e:
                print(f"Unexpected error: {e}")

def virustotal_hash_check(file_hash):
    print("Checking VIrustotal)")
    headers = {"x-apikey": API_KEY}
    response = requests.get(VT_URL + file_hash, headers=headers)
    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})

        # Extract scan statistics
        total_scans = attributes.get("last_analysis_stats", {})
        malicious = total_scans.get("malicious", 0)
        suspicious = total_scans.get("suspicious", 0)
        undetected = total_scans.get("undetected", 0)

        # Extract additional metadata
        first_seen = attributes.get("first_submission_date", "N/A")
        last_analysis_date = attributes.get("last_analysis_date", "N/A")
        threat_label = attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "None")

        return [malicious, suspicious, undetected, first_seen, last_analysis_date, threat_label]

    return ["Error"] * 6  


def update_csv(outputfile):
    print("started Updating with virustotal)")
    with open(outputfile, "r", newline="") as infile:
        reader = csv.reader(infile)
        rows = list(reader) 
    header = rows[0]

    # Check if new columns exist, if not, add them
    if not all(col in header for col in new_columns):
        header.extend(new_columns)

    # Step 2: Process each row, appending new VirusTotal data if missing
    updated_rows = [header]  # Start with updated headers

    for i in range(1, len(rows)):
        row = rows[i]
        file_hash = row[-1]  # Hash is in the last column

        # Check if row already has VirusTotal data (avoid duplicate API calls)
        if len(row) >= len(header):
            updated_rows.append(row)  # Keep existing data
            continue

        # Query VirusTotal and append results
        result = virustotal_hash_check(file_hash)
        row.extend(result)

        updated_rows.append(row)  # Add updated row

        time.sleep(16)  # Respect VirusTotal API rate limit (4 requests/min)

    # Step 3: Write back the updated data (overwrite the file safely)
    with open(outputfile, "w", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerows(updated_rows)

    print(f"✅ CSV updated successfully with VirusTotal data!")


def main():
    print("script started")
    if platform.system() !="Windows":
        print("This Script is Designed for Windows ONLY!")
        return
    get_process_info(outputfile)
    update_csv(outputfile)

    
if __name__ == "__main__":
    main()