import platform
import subprocess
import re
import pickle
import requests
import socket
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv('API_KEY')
if API_KEY:
    print(f"API Key: {API_KEY}")
else:
    print("API Key not found")

IPV4_IPV6_HOST_REGEX = re.compile(
    r'(?:(?:\d{1,3}\.){3}\d{1,3})|'  # IPv4
    r'(?:(?:[a-fA-F0-9:]+:+)+[a-fA-F0-9]+)|' # IPv6
    r'(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})' # Hostname
)

VALID_HOSTNAME_REGEX = re.compile(
        r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*"  # Subdomains (optional)
        r"([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"  # Main domain
    )

def run_command():
    if platform.system() == 'Windows':
        """netstat -n Displays addresses and port numbers in numerical forms
           netstat -a Displays all connections and listening ports
           which are ESTABLISHED"""
         
        netstatProcess = subprocess.Popen(["netstat", "-na"], stdout=subprocess.PIPE, text=True)
        grepProeess = subprocess.Popen(["findstr", "ESTABLISHED"], stdin=netstatProcess.stdout, stdout=subprocess.PIPE, text=True) 
        output = grepProeess.communicate()
        return output[0]
    else:
        # for Linux, MacOS
        netstatProcess = subprocess.Popen(["netstat", "-na"], stdout=subprocess.PIPE, text=True)
        grepProeess = subprocess.Popen(["grep", "ESTABLISHED"], stdin=netstatProcess.stdout, stdout=subprocess.PIPE, text=True)
        output = grepProeess.communicate()
        return output[0]
    
def is_public_ip(ip):
    
    if ":" in ip:
        return not ip.startswith("fe80", "fc", "fd", "ff") 

    octets = list(map(int, ip.strip().split('.')[:2]))
    if ip.startswith("127.") or ip.startswith("::1"): return False
    if octets[0] == 10: return False
    if octets[0] == 172 and 16 <= octets[1] < 32: return False
    if octets[0] == 192 and octets[1] == 168: return False
    
    return True

def extract_destination_address(output):
    matches = IPV4_IPV6_HOST_REGEX.findall(output)
    
    cleaned_matches = []
    for match in matches:
        parts = match.split('.')
        if len(parts) > 4 and parts[-1].isdigit():
            match = '.'.join(parts[:-1])

        if not match.replace('.', '').isdigit() or is_public_ip(match):
            cleaned_matches.append(match)
    
    return set(cleaned_matches)

def get_hostnames(addresses):
    return {address for address in addresses if VALID_HOSTNAME_REGEX.match(address)}


def get_ip_addresses_from_hostname(hostnames):
    ip_addreses_from_hostnames = set()
    
    for hostname in hostnames:
        try:
            ip = socket.gethostbyname(hostname)
            ip_addreses_from_hostnames.add(ip)
        except socket.gaierror:
            print(f'Could not resolve hostname: {hostname}')

    return ip_addreses_from_hostnames

def all_addresses(updated_addresses):
    hostnames = get_hostnames(updated_addresses)
    if hostnames:
        resolved_ips = get_ip_addresses_from_hostname(hostnames)
        only_ip_addresses = updated_addresses - hostnames
        all_ips = only_ip_addresses.union(resolved_ips)
    else:
        all_ips = updated_addresses

    return all_ips



#print(all_ip_addresses)
#run_command()

#addresses = extract_destination_address(run_command())

def write_file(addresses):
    file = open("connections.txt", "wb")
    pickle.dump(addresses, file)
    file.close()


def read_file():
    try:
        file = open("connections.txt", "rb")
        return pickle.load(file)
    except (EOFError, FileNotFoundError):
        return set()

def update_file(addresses):
    existing_addresses = read_file()
    updated_addresses = existing_addresses.union(addresses)
    
    write_file(updated_addresses)
    return updated_addresses
    

#updated_addresses = update_file(addresses)
#print(updated_addresses)
#print(len(updated_addresses))

set1 = {'18.204.248.254', '142.250.178.14', '142.250.200.14', '2.18.190.175', '74.125.71.188', '2.18.190.164', '20.187.53.93', '108.156.38.75', '18.165.201.85', '52.19.36.133', '2.18.27.82', '54.195.60.28', '216.58.212.225', '216.58.213.2', '140.82.113.22', '172.64.155.209', '54.88.172.139', '69.173.156.139', '52.123.242.28', '216.58.204.68', '140.82.112.22', '18.154.84.45', '142.250.179.226', '35.227.252.103', '34.160.55.127', '34.32.10.90', '172.64.144.166', '172.217.16.226', '54.161.34.85', '23.208.246.75', '35.186.253.211', '37.157.6.230', '142.250.200.46', '127.0.0.1', '142.250.79.163', '216.58.213.10', '184.26.189.197', '52.205.30.12', '18.245.214.181', '35.214.199.88', '104.208.16.88', '142.251.168.84', '172.217.169.1', '142.250.178.2', '35.190.80.1', '104.18.26.193', '204.79.197.204', '172.217.169.33', '52.112.120.233', '142.250.178.1', '51.89.9.252', '37.252.171.52', '185.89.211.116', '13.107.246.64', '15.204.162.93', '140.82.113.21', '192.168.1.200', '104.16.118.43', '142.250.200.1', '52.158.227.125', '37.157.6.254', '104.26.12.193', '172.217.169.14', '142.250.179.227', '142.250.187.238', '40.99.201.162', '216.58.212.194', '185.59.127.173', '142.250.187.202', '52.6.244.63', '142.250.180.1', '18.244.179.124', '104.18.32.47', '34.120.63.153', '52.84.90.96', '142.250.179.225', '3.233.158.24', '142.250.178.3', '92.223.24.5', '142.250.187.194', '142.250.187.195', '142.250.200.33', '34.1.1.166', '142.250.180.3', '142.250.187.193', '13.89.179.13', '52.123.135.6', '13.89.178.27', '98.82.241.158', '52.209.231.43', '52.112.120.223', '172.217.169.2', '20.90.152.133', '34.141.12.164', '142.250.178.10', '18.193.208.240', '178.250.1.38', '92.223.24.4', '107.22.168.163', '104.18.27.193', '2.18.27.145', '52.20.97.175', '20.42.73.31', '74.125.168.134', '216.58.204.65', '54.244.24.226', '172.217.169.65', '52.123.159.178', '52.168.117.171', '13.216.94.91', '143.244.197.139', '52.208.94.165', '52.73.93.165', '142.250.183.131', '35.244.174.68', '216.58.201.98', '54.147.250.19', '142.250.200.2', '54.164.73.123', '142.250.180.14', '52.178.17.2', '172.217.169.66', '54.211.79.35', '52.37.245.108', '34.111.24.1', '3.226.194.238', '103.231.98.76', '64.233.167.84', '51.89.9.254', '20.42.65.88', '98.82.53.89', '51.132.193.104', '20.26.156.210', '163.5.194.36', '34.98.110.65', '142.250.200.34', '20.199.39.224', '104.208.16.92', '45.55.125.114', '157.240.221.61', '52.123.128.14', '216.239.32.36', 
'64.233.184.188', '185.64.190.77'}
# 144
set2 = {'37.157.6.254', '13.107.246.64', '54.211.79.35', '35.186.253.211', '52.209.231.43', '142.250.183.131', '142.250.79.163', '34.120.63.153', '172.217.169.1', '20.42.73.31', '140.82.113.22', '184.26.189.197', '142.250.187.195', '52.37.245.108', '64.233.167.84', '104.18.32.47', '216.58.213.10', '52.84.90.96', '20.90.152.133', '54.147.250.19', '34.98.110.65', '185.89.211.116', '52.208.94.165', '34.160.55.127', '143.244.197.139', '104.18.27.193', '178.250.1.38', '104.208.16.88', '18.193.208.240', '172.217.169.66', '13.89.179.13', '104.18.26.193', '52.19.36.133', '34.141.12.164', '216.58.204.68', '172.217.169.33', '216.58.212.194', '142.250.178.3', '142.250.187.202', '20.26.156.210', '34.32.10.90', '142.250.178.1', '45.55.125.114', '127.0.0.1', '108.156.38.75', '140.82.112.22', '54.195.60.28', '52.168.117.171', '216.239.32.36', '2.18.27.82', '52.178.17.2', '20.42.65.88', '18.245.214.181', '142.251.168.84', '69.173.156.139', '3.233.158.24', '98.82.241.158', '172.217.16.226', '104.26.12.193', '204.79.197.204', '54.161.34.85', '18.244.179.124', '140.82.113.21', '52.6.244.63', '163.5.194.36', '34.111.24.1', '185.64.190.77', '172.64.155.209', '142.250.187.238', '52.20.97.175', '92.223.24.4', '64.233.184.188', '142.250.179.226', '103.231.98.76', '192.168.1.200', '13.89.178.27', '172.217.169.2', '98.82.53.89', '13.216.94.91', '34.1.1.166', '142.250.178.10', '142.250.200.46', '142.250.200.14', '51.89.9.252', '23.208.246.75', '20.199.39.224', '74.125.168.134', '172.217.169.65', '104.208.16.92', '54.244.24.226', '142.250.179.225', '52.158.227.125', '18.204.248.254', '107.22.168.163', '15.204.162.93', '216.58.213.2', '104.16.118.43', '2.18.190.175', '2.18.27.145', '142.250.178.2', '142.250.200.33', '142.250.180.14', '40.99.201.162', '142.250.200.1', '51.89.9.254', '35.214.199.88', '52.123.242.28', '3.226.194.238', '185.59.127.173', '172.217.169.14', '142.250.200.34', '216.58.204.65', '2.18.190.164', '20.187.53.93', '52.123.128.14', '37.157.6.230', '35.227.252.103', '216.58.212.225', '142.250.178.14', '92.223.24.5', '142.250.180.1', '74.125.71.188', '52.123.135.6', '157.240.221.61', '142.250.179.227', '172.64.144.166', '18.154.84.45', '35.244.174.68', '52.123.159.178', '216.58.201.98', '54.88.172.139', '52.112.120.223', '142.250.187.194', '35.190.80.1', '54.164.73.123', '18.165.201.85', '52.112.120.233', '142.250.180.3'}
#138

#print(set1 - set2) # len(6)

def check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': '',
    }

    headers = {
        'Key': API_KEY,
        'Accept': 'application/json',
    }

    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status() # Raise error if no 200 status code

        response_json = response.json()
        if 'data' not in response_json:
            raise ValueError("No data in response")

        attributes = response_json['data']

        return {
            'ip': attributes['ipAddress'], 
            'isp': attributes['isp'],
            'Abuse Confidence Score': attributes['abuseConfidenceScore'],
            'is Whitelisted': attributes['isWhitelisted'],
            'Domain': attributes['domain'],
        }
    
    except requests.exceptions.HTTPError as http_error:
        print(f"HTTP error occurred: {http_error}")
    
    except requests.exceptions.RequestException as request_exception:    
        print(f"Request exception occurred: {request_exception}")


if __name__ == "__main__":
    run_command()
    addresses = extract_destination_address(run_command())

    updated_addresses = update_file(addresses)
    print(updated_addresses)
    all_ip_addresses = all_addresses(addresses)
    for ip in updated_addresses:
        print(check_ip(ip))




'''updated_addresses = "google.com, 8.8.8.8, 2606:4700:4700::1111, yahoo.co.uk, microsoft.com 192.168.1.1 sub.domain-example.org"

addresses = extract_destination_address(updated_addresses)
all_ip_addresses = all_addresses(addresses)
print(all_ip_addresses)
for ip in all_ip_addresses:
    print(check_ip(ip)) '''
#print(get_hostnames(updated_addresses))
#print(get_ip_addresses_from_hostname(get_hostnames(updated_addresses)))