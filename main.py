#!/usr/bin/env python3
import argparse
import subprocess
import sys
import time
from pathlib import Path

def run_network_analysis():
    """Execute netcon.py for network analysis"""
    print("\n🔍 Running Network Analysis...")
    try:
        result = subprocess.run([sys.executable, "netcon.py"], check=True)
        if result.returncode == 0:
            print("✅ Network analysis completed successfully")
            print("   Generated files: network_connections.csv, foreign_addresses.csv, abuse_report.csv")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Network analysis failed: {e}")
        return False

def run_process_analysis():
    """Execute process_analysis.py for process scanning"""
    print("\n🔍 Running Process Analysis...")
    try:
        result = subprocess.run([sys.executable, "process_analysis.py"], check=True)
        if result.returncode == 0:
            print("✅ Process analysis completed successfully")
            print("   Generated file: process_report.csv")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Process analysis failed: {e}")
        return False

def check_environment():
    """Verify required files and environment"""
    if not Path('.env').exists():
        print("❌ Error: .env file not found. Please create one with your API keys.")
        print("   Required keys: VIRUSTOTAL_API_KEY and ABUSEIP_API_KEY")
        return False
    
    required_scripts = ['netcon.py', 'process_analysis.py']
    missing = [script for script in required_scripts if not Path(script).exists()]
    
    if missing:
        print(f"❌ Error: Missing required script(s): {', '.join(missing)}")
        return False
    
    return True

def print_banner():
    """Display the tool banner"""
    banner = r"""                                                                  
  Automated Forensic Analysis Tool
  """
    print(banner)

def main():
    print_banner()
    
    if not check_environment():
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description='Auto-Forensic Tool - System and Network Analysis')
    parser.add_argument('--full-scan', action='store_true', help='Complete system analysis (processes + network)')
    parser.add_argument('--network-only', action='store_true', help='Scan network connections only')
    parser.add_argument('--process-only', action='store_true', help='Scan running processes only')
    
    args = parser.parse_args()
    
    start_time = time.time()
    
    if args.network_only:
        run_network_analysis()
    elif args.process_only:
        run_process_analysis()
    else:
        # Default to full scan if no specific option is provided
        print("🚀 Starting Full System Analysis...")
        network_success = run_network_analysis()
        process_success = run_process_analysis()
        
        if network_success and process_success:
            print("\n✅ All operations completed successfully!")
            print("   Generated reports:")
            print("   - Network: network_connections.csv, foreign_addresses.csv, abuse_report.csv")
            print("   - Processes: process_report.csv")
    
    elapsed = time.time() - start_time
    print(f"\n⏱️  Execution time: {elapsed:.2f} seconds")

if __name__ == "__main__":
    main()
