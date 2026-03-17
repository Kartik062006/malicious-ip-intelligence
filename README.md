# Malicious IP Intelligence System

An automated threat intelligence tool designed to scan, analyze, and classify IP addresses using the VirusTotal API (v3). 

This Python-based Security Operations (SecOps) script reads a list of network IP addresses, queries them against established security vendors, and categorizes them as **Safe**, **Suspicious**, or **Malicious**. It automatically handles API rate limiting and generates both a console summary and a hard-copy text report for incident response.

## Features
* **Automated Threat Hunting:** Rapidly analyzes bulk IP addresses from network logs.
* **Granular Classification:** Evaluates engine analysis statistics to flag both suspicious and definitively malicious nodes.
* **Operational Security:** Utilizes environment variables (`.env`) to keep API keys secure and out of version control.
* **Rate Limit Handling:** Built-in logic to respect free-tier API constraints without failing.
* **Automated Reporting:** Generates a clean, categorized `flagged_ips_report.txt` artifact for security teams.

## Prerequisites
* Python 3.12
* A free [VirusTotal API Key](https://www.virustotal.com/)

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Kartik062006/malicious-ip-intelligence.git](https://github.com/Kartik062006/malicious-ip-intelligence)
   cd malicious-ip-intelligence

2. **Install the required Python libraries:**
   ```bash
   pip install requests python-dotenv

3. **Secure Your API Key**
   * Create a file named .env in the root directory.
   * Add your VirusTotal API key to the file:
     ```bash
     VT_API_KEY=your_actual_api_key_here
   * Note: Ensure .env is listed in your .gitignore file.

4. **Prepare your data:**
   * Create a text file named ips.txt in the root directory.
   * Add the IP addresses you want to scan (one per line).
  
5. **Usage**
   Run the script from your terminal
   ```bash
   python vt_scanner.py

6. **Expected Output**
   The script will output real-time scanning progress to the console and automatically generate a flagged_ips_report.txt file containing the separated lists of
   Suspicious and Malicious IP addresses requiring mitigation.
   
7. **Disclaimer**
   This tool was developed as a cybersecurity training project. Always ensure you have the proper authorization before scanning network infrastructure or
   interacting with third-party threat intelligence APIs.
