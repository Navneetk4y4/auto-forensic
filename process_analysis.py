import psutil
import csv
from datetime import datetime
import hashlib
import ctypes
import platform
outputfile="process_report.csv"

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
        print("Opening Writer")
        writer.writerow(["PID", "PPID", "Name", "Executable Path", "CMD Command", "User", "Status", 
                         "Creation Time","Working Directory", "Memory Usage (MB)", "Read Count", "Write Count", "SHA256"])

        for proc in psutil.process_iter(attrs=['pid','ppid','name', 'exe','cmdline', 'username','status','create_time', 'cwd','memory_info','open_files','io_counters']):

            try:
                print("fetching process data")
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
                print("Writing to CSV file...")

                writer.writerow([pid,ppid,name, exe_path,cmdline, username,status,create_time, cwd,round(memory_info, 2), read_count, write_count, file_hash])
            except psutil.NoSuchProcess as e:
                print(f"Process no longer exists: {e}")
            except psutil.AccessDenied as e:
                print(f"Access denied to process: {e}")
            except psutil.ZombieProcess as e:
                print(f"Zombie process encountered: {e}")
            except Exception as e:
                print(f"Unexpected error: {e}")

 

def main():
    print("script started")
    if platform.system() !="Windows":
        print("This Script is Designed for Windows ONLY!")
        return
    get_process_info(outputfile)

    
if __name__ == "__main__":
    main()