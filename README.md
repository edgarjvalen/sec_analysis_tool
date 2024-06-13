## VirusTotal API Analysis Tool

## Summary
This project is a comprehensive tool designed to enhance cybersecurity by leveraging the power of VirusTotal's API. It provides functionality to analyze files, hashes, domains, and IP addresses for potential threats. Using Python libraries such as requests, psutil, hashlib, and prettytable, the tool offers a user-friendly interface to perform security checks and present the results in a well-organized, colored format.

## Steps of the Code
1. **Import Necessary Libraries**
The script starts by importing essential libraries, including os, hashlib, requests, psutil, colorama, and prettytable.

```commandline
pip install requests psutil colorama prettytable
```

2. **Initialize Colorama**
Colorama is initialized to enable colored output in the terminal, which enhances readability and highlights important information.

3. **Define VirusTotal API Constants**
The API key and base URLs for VirusTotal's file, domain, and IP endpoints are defined.

4. **ASCII Art**
An ASCII art logo is printed to give a visual appeal to the tool.

5. **SHA-256 Hash Calculation**
A function calculate_sha256 is defined to calculate the SHA-256 hash of a file. This function reads the file in blocks to avoid memory issues with large files.

6. **VirusTotal API Interaction**
Functions are defined to interact with VirusTotal's API for different types of checks:

check_hash_with_virustotal: Checks the SHA-256 hash of a file.
check_domain_with_virustotal: Checks a domain for threats.
check_ip_with_virustotal: Checks an IP address for threats.

7. **Process Executable Path Retrieval**
A helper function get_process_executable_path is defined to retrieve the executable path of a running process by its name.

8. **Display Results**
Functions are defined to display the results of the VirusTotal checks in a formatted and readable manner using PrettyTable:

display_results: Displays results for file, hash, and IP checks.
display_domain_results: Displays results for domain checks.

9. **Main Function**
The main function provides a user interface to choose between analyzing a file, hash, domain, or IP address. It handles user input, performs the chosen analysis, and displays the results.

10. **Script Execution**
The script is set to execute the main function when run directly.

## Future Ways to Escalate the Code Project

1. **Enhanced Error Handling**
Implement more robust error handling and logging mechanisms to ensure the tool can gracefully handle unexpected issues.

2. **Scheduled Scans**
Add functionality to schedule periodic scans of specified files, domains, or IP addresses, and send notifications or reports based on the results.

3. **Expanded API Integration**
Integrate with additional security APIs to provide a broader range of threat intelligence and enhance the tool's detection capabilities.

4. **Multi-Platform Support**
Ensure compatibility with different operating systems, including Windows, macOS, and various Linux distributions.

## Code

```commandline
import os
import hashlib
import requests
import psutil
from colorama import Fore, init
from prettytable import PrettyTable

init(autoreset=True)

VIRUSTOTAL_API_KEY = 'your_api_key_here'
VIRUSTOTAL_FILE_URL = 'https://www.virustotal.com/api/v3/files/'
VIRUSTOTAL_DOMAIN_URL = 'https://www.virustotal.com/api/v3/domains/'
VIRUSTOTAL_IP_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'

hasher_art = r"""
_________ .__                   __     _____.___.          _________      .__   _____ 
\_   ___ \|  |__   ____   ____ |  | __ \__  |   |____     /   _____/ ____ |  |_/ ____\
/    \  \/|  |  \_/ __ \_/ ___\|  |/ /  /   |   \__  \    \_____  \_/ __ \|  |\   __\ 
\     \___|   Y  \  ___/\  \___|    <   \____   |/ __ \_  /        \  ___/|  |_|  |   
 \______  /___|  /\___  >\___  >__|_ \  / ______(____  / /_______  /\___  >____/__|  
        \/     \/     \/     \/     \/  \/           \/          \/     \/        
"""
print(hasher_art)

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_hash_with_virustotal(hash_value):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(VIRUSTOTAL_FILE_URL + hash_value, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {'error': 'Hash not found on VirusTotal'}
        else:
            return {Fore.RED + 'error': 'Failed to retrieve result from VirusTotal. Status code: ' + str(response.status_code)}
    except Exception as e:
        return {'error': 'An error occurred: ' + str(e)}

def get_process_executable_path(process_name):
    for proc in psutil.process_iter(['name', 'exe']):
        try:
            if proc.info['name'].lower() == process_name.lower():
                return proc.info['exe']
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return None

def check_domain_with_virustotal(domain):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    url = f"{VIRUSTOTAL_DOMAIN_URL}{domain}"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {Fore.RED + 'error': 'Domain not found on VirusTotal'}
        else:
            return {Fore.RED + 'error': 'Failed to retrieve result from VirusTotal. Status code: ' + str(response.status_code)}
    except Exception as e:
        return {'error': 'An error occurred: ' + str(e)}

def check_ip_with_virustotal(ip):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    url = f"{VIRUSTOTAL_IP_URL}{ip}"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {Fore.RED + 'error': 'Failed to retrieve result from VirusTotal. Status code: ' + str(response.status_code)}
    except Exception as e:
        return {'error': 'An error occurred: ' + str(e)}

def display_results(result, item_type):
    if 'error' in result:
        print(Fore.WHITE + "Error:", result['error'])
    else:
        if 'data' in result and 'attributes' in result['data']:
            attributes = result['data']['attributes']
            if 'last_analysis_stats' in attributes:
                if attributes['last_analysis_stats']['malicious'] > 0:
                    print(Fore.RED + f"Red flags found ({item_type} - VirusTotal).")
                    table = PrettyTable()
                    table.field_names = [Fore.WHITE + "Engine", Fore.WHITE + "Threat"]
                    for engine, analysis_result in attributes['last_analysis_results'].items():
                        if analysis_result['category'] == 'malicious':
                            table.add_row([Fore.WHITE + engine, Fore.WHITE + analysis_result['result']])
                    print(table)
                else:
                    print(Fore.GREEN + f"{item_type.capitalize()} scans clean (VirusTotal)")
            else:
                print(Fore.RED + f"Scan result not available ({item_type} - VirusTotal)")
        else:
            print(Fore.RED + f"Scan result not available ({item_type} - VirusTotal)")
            
def display_domain_results(result):
    if 'error' in result:
        print(Fore.WHITE + "Error:", result['error'])
    else:
        if 'data' in result and 'attributes' in result['data']:
            attributes = result['data']['attributes']
            if 'last_analysis_stats' in attributes:
                if attributes['last_analysis_stats']['malicious'] > 0:
                    print(Fore.RED + "Red flags found (domain - VirusTotal).")
                    table = PrettyTable()
                    table.field_names = [Fore.WHITE + "Engine", Fore.WHITE + "Threat"]
                    for engine, analysis_result in attributes['last_analysis_results'].items():
                        if analysis_result['category'] == 'malicious':
                            table.add_row([Fore.WHITE + engine, Fore.WHITE + analysis_result['result']])
                    print(table)
                else:
                    print(Fore.GREEN + "Domain scans clean (VirusTotal)")
            else:
                print(Fore.LIGHTRED_EX + "Scan result not available (domain - VirusTotal)")
        else:
            print(Fore.LIGHTRED_EX + "Scan result not available (domain - VirusTotal)")
def main():
    print(Fore.LIGHTYELLOW_EX + "Choose what you want to analyze:")
    print("1. File")
    print("2. Hash")
    print("3. Domain")
    print("4. IP")
    choice = input(Fore.LIGHTYELLOW_EX + "Enter your choice (1-4): ").strip()

    if choice == '1':
        file_name = input("Enter the name of the PDF document: ")
        file_path = os.path.abspath(file_name)
        if os.path.exists(file_path):
            sha256_hash = calculate_sha256(file_path)
            print("SHA256 Hash of the file:", sha256_hash)
            result = check_hash_with_virustotal(sha256_hash)
            display_results(result, "file")
        else:
            print(Fore.LIGHTYELLOW_EX + "File not found.")
    elif choice == '2':
        hash_value = input("Enter the hash to check: ").strip()
        result = check_hash_with_virustotal(hash_value)
        display_results(result, "hash")
    elif choice == '3':
        domain = input("Enter the domain to check: ").strip()
        result = check_domain_with_virustotal(domain)
        display_domain_results(result)
    elif choice == '4':
        ip = input("Enter the IP address to check: ").strip()
        result = check_ip_with_virustotal(ip)
        display_results(result, "ip")
    else:
        print(Fore.RED + "Invalid choice. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    main()
```
