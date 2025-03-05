from config import NETBOX_URL as netbox_url, API_TOKEN_ADMIN as api_token
import requests
import json
import subprocess
import re
import platform
import csv
import socket

def check_config():
    if not netbox_url:
        return False
    if not api_token:
        return False
    return True


headers = {
    'Authorization': f'Token {api_token}',
    'Content-Type': 'application/json',
}


def find_available_tenants():
    tenant_url = f'{netbox_url}/api/tenancy/tenants/'
    try:
        response = requests.get(tenant_url, headers=headers, timeout=5)
        tenant_data = response.json()
        return tenant_data
    except requests.exceptions.ConnectionError:
        print("Connection error: The server might be down.")
    except requests.exceptions.Timeout:
        print("Connection timeout: The server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return exit(1)

def get_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None

def scan_subnet(subnet):
    if platform.system() == "Linux":
        command = ["sudo", "nmap", "-sn", subnet]
    elif platform.system() == "Windows":
        command = ["nmap", "-sn", subnet]
    else:
        exit(1)

    result = subprocess.run(command, capture_output=True, text=True)

    devices = []

    host = None
    for line in result.stdout.splitlines():
        if "Nmap scan report for" in line:
            ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip:
                ip = ip.group(1)
                hostname = get_hostname(ip)
                host = {
                    "id": None,
                    "interface_id": None,
                    "ip_addr_id": None,
                    "ip_addr": ip,
                    "hostname": hostname,
                    "status": "offline",
                    "mac_addr": "",
                    "manufacturer": "Unspecified"
                }
            continue

        if "Host is up" in line and host:
            host["status"] = "active"
            continue
        elif "Host is down" in line and host:
            host["status"] = "offline"
            continue

        if "MAC Address" in line and host:
            mac_info = re.findall(r"MAC Address: (\S+) \(([^)]+)\)", line)
            if mac_info:
                host["mac_addr"], host["manufacturer"] = mac_info[0]
                if host["manufacturer"] == "Unknown":
                    host["manufacturer"] = "Unspecified"
            if host and "MAC Address" in line:
                devices.append(host)
                host = None
                continue

    return devices

# Funkcia na ziskavanie host name, pre lepsiu evidenciu a rozoznanie pocitacov



def create_device(device, tenant):
    name = device["hostname"]
    if name == None:
        name = device["mac_addr"]

    payload = {
        "name": name,
        "role": 17, # Ziskat predtym
        "device_type": 9, # Ziskat predtym
        "site": 6, # Ziskat predtym
        # "location": "", # Location, miestnost, napr: C603, ak neexistuje, vytvori sa v NetBoxe
        "status": device["status"], # Je iny status neaktivny pre ip addr a pre device
        "tenant": tenant # Zvoleny tenant pouzivatelom
    }

    device_ulr = f"{netbox_url}/api/dcim/devices/"

    try:
        response = requests.post(device_ulr, json=payload, headers=headers, timeout=5)
        if response.status_code == 201:
            device["id"] = response.json().get("id", [])
            print(f"Device {device['hostname']} with MAC Address {device['mac_addr']} added successfully.")
        else:
            print(f"Failed to add Device {device['hostname']} with MAC Address {device['mac_addr']}. {response.status_code} {response.text}")
        return device
    except requests.exceptions.ConnectionError:
        print("Connection error: The server might be down.")
    except requests.exceptions.Timeout:
        print("Connection timeout: The server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return exit(1)

def create_interface(device):
    if device["id"] == None:
        return

    payload = {
        "device": device["id"],
        "name": "eth0",
        "type": "other", # Manualne nastavit
        "mac_address": device["mac_addr"],
    }

    interface_url = f"{netbox_url}/api/dcim/interfaces/"

    try:
        response = requests.post(interface_url, json=payload, headers=headers, timeout=5)
        print(json.dumps(response.json(), indent=1))

        if response.status_code == 201:
            device["interface_id"] = response.json().get("id", [])
            print(f"Interface of a Device {device['hostname']} with {device['interface_id']} with MAC Address {device['mac_addr']} added successfully.")
        else:
            print(f"Failed to add Interface of a Device {device['hostname']} with MAC Address {device['mac_addr']}. {response.status_code} {response.text}")
        return device
    except requests.exceptions.ConnectionError:
        print("Connection error: The server might be down.")
    except requests.exceptions.Timeout:
        print("Connection timeout: The server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return exit(1)

def create_address(device, tenant):
    print(f"Interface id {device['interface_id']}")

    payload = {
        "address": f"{device['ip_addr']}/24",
        "status": "active",
        "tenant": tenant,
        "description": device["mac_addr"],
        "assigned_object_type": "dcim.interface",
        "assigned_object_id": device["interface_id"],
    }

    ip_address_url = f"{netbox_url}/api/ipam/ip-addresses/"

    try:
        response = requests.post(ip_address_url, json=payload, headers=headers, timeout=5)
        if response.status_code == 201:
            device["ip_addr_id"] = response.json().get("id", [])
            print(f"IP Address {device['ip_addr']} has been added successfully.")
        else:
            print(f"Failed to add IP Address {device['ip_addr']}. {response.status_code} {response.text}")
        return device

    except requests.exceptions.ConnectionError:
        print("Connection error: The server might be down.")
    except requests.exceptions.Timeout:
        print("Connection timeout: The server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return exit(1)

def update_device(device):
    # device_entity = get_device(device)

    payload = {
        "role": 17, # Ziskat predtym
        "device_type": 9, # Ziskat predtym
        "site": 6, # Ziskat predtym
        "primary_ip4": device["ip_addr_id"]
    }

    device_url = f"{netbox_url}/api/dcim/devices/{device['id']}/"

    try:
        response = requests.put(device_url, json=payload, headers=headers, timeout=5)
        if response.status_code == 200:
            print("OK")
            print(f"Device with ID {device['id']} has been updated successfully with primary IP {device['ip_addr']}.")
        else:
            print("FAIL")
            print(f"Failed to update device with ID {device['id']}. {response.status_code} {response.text}")
        return

    except requests.exceptions.ConnectionError:
        print("Connection error: The server might be down.")
    except requests.exceptions.Timeout:
        print("Connection timeout: The server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return exit(1)



def get_device(device):
        device_url = f"{netbox_url}/api/dcim/devices/{device['id']}/"
        try:
            response = requests.get(device_url, headers=headers, timeout=5)
            if response.status_code == 200:
                device_data = response.json()
                print(f"Successfully retrieved device with ID {device['id']}:")
                print(device_data)
                return device_data
            else:
                print(f"Failed to retrieve device with ID {device['id']}. {response.status_code} {response.text}")
                return None
        except requests.exceptions.ConnectionError:
            print("Connection error: The server might be down.")
        except requests.exceptions.Timeout:
            print("Connection timeout: The server took too long to respond.")
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
        return exit(1)



def main():
    if not check_config():
        print('Invalid config file. Check config.py.')
        return 1

    tenants = find_available_tenants()
    if tenants["count"] == 0:
        print("Permission denied.")
        exit(0)

    # subnet = str(input("Enter the subnet with mask: "))
    devices = scan_subnet("192.168.100.0/24")

    for device in devices:
        device = create_device(device, tenant=1)
        device = create_interface(device)
        device = create_address(device, tenant=1)
        update_device(device)

    # tenant = display_tenant_options(tenants)

    # print(json.dumps(hosts_metadata, indent=1))
    # export_csv(hosts_metadata)

if __name__ == "__main__":
    main()