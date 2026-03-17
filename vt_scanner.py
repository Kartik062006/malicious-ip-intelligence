import requests
import time
import os
from dotenv import load_dotenv

# Load the hidden API key from your .env file
load_dotenv()
API_KEY = os.getenv('VT_API_KEY')

if not API_KEY:
    print("Error: API key not found. Please check your .env file.")
    exit()

HEADERS = {
    "accept": "application/json",
    "x-apikey": API_KEY
}

def check_ip_reputation(ip):
    """Queries the VirusTotal API for a specific IP address."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip.strip()}"
    
    try:
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error querying {ip}: HTTP {response.status_code}")
            return None
    except Exception as e:
        print(f"Connection error for {ip}: {e}")
        return None

def classify_ip(stats):
    """Classifies the IP based on the engine analysis stats."""
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    
    if malicious > 0:
        return "Malicious"
    elif suspicious > 0:
        return "Suspicious"
    else:
        return "Safe"

def main():
    print("--- Starting Malicious IP Intelligence System ---")
    
    malicious_ips = []
    suspicious_ips = []
    
    # Read IPs from the text file
    try:
        with open('ips.txt', 'r') as file:
            ip_list = file.readlines()
    except FileNotFoundError:
        print("Error: ips.txt file not found.")
        return

    # Process each IP address
    for ip in ip_list:
        ip = ip.strip()
        if not ip:
            continue
            
        print(f"\nChecking IP: {ip}...")
        data = check_ip_reputation(ip)
        
        if data:
            stats = data['data']['attributes']['last_analysis_stats']
            classification = classify_ip(stats) 
            
            print(f"Result: {classification}")
            print(f"Details: {stats['malicious']} Malicious, {stats['suspicious']} Suspicious, {stats['harmless']} Harmless")
            
            # Sort the IPs into their respective lists
            if classification == "Malicious":
                malicious_ips.append(ip)
            elif classification == "Suspicious":
                suspicious_ips.append(ip)
        
        # Free API tier limit is 4 requests per minute. Sleeping for 16 seconds prevents errors.
        print("Waiting for rate limit...")
        time.sleep(16) 

    # Generate the final console report
    print("\n--- Final Scan Report ---")
    
    if malicious_ips:
        print("\n[!] WARNING: The following Malicious IPs were detected (Action Required):")
        for mip in malicious_ips:
            print(f" - {mip}")
    else:
        print("\n[*] No malicious IPs detected in this scan.")
        
    if suspicious_ips:
        print("\n[?] NOTICE: The following Suspicious IPs were detected (Monitor Closely):")
        for sip in suspicious_ips:
            print(f" - {sip}")
    else:
        print("\n[*] No suspicious IPs detected in this scan.")

    # Generate the text file report
    print("\n--- Generating File Report ---")
    report_filename = "flagged_ips_report.txt"
    try:
        with open(report_filename, 'w') as f:
            f.write("--- Automated Threat Intelligence Scan Results ---\n\n")
            
            f.write("[!] MALICIOUS IPs (Action Required):\n")
            if malicious_ips:
                for ip in malicious_ips:
                    f.write(f"{ip}\n")
            else:
                f.write("None detected.\n")
                
            f.write("\n[?] SUSPICIOUS IPs (Monitor Closely):\n")
            if suspicious_ips:
                for ip in suspicious_ips:
                    f.write(f"{ip}\n")
            else:
                f.write("None detected.\n")
                
        print(f"[+] Successfully saved flagged IPs to {report_filename}")
    except IOError as e:
        print(f"[-] Error writing to file: {e}")

if __name__ == "__main__":
    main()