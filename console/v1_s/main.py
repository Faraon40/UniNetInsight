from config import NETBOX_URL as netbox_url, API_TOKEN_ADMIN as api_token
import requests
import json
import subprocess
import re
import platform
import csv
import socket
import sys


headers = {
    'Authorization': f'Token {api_token}',
    'Content-Type': 'application/json',
}


def check_config():
    if not netbox_url:
        print("Missing NetBox url in config.py.")
        sys.exit(1)
    if not api_token:
        print("Missing NetBox api key in config.py.")
        sys.exit(1)


def find_available_tenants():
    tenant_url = f'{netbox_url}/api/tenancy/tenants/'

    try:
        response = requests.get(tenant_url, headers=headers, timeout=5)
        tenant_data = response.json()

        if "detail" in tenant_data and tenant_data["detail"] == "Invalid token":
            print("Error: Invalid token. Please check your authentication.")
        elif "count" in tenant_data and tenant_data["count"] == 0:
            print("Permission denied.")
        else:
            return tenant_data

    except requests.exceptions.ConnectionError:
        print("Connection error: The server might be down.")
    except requests.exceptions.Timeout:
        print("Connection timeout: The server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return sys.exit(1)


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
    print(f"Scanning subnet {subnet} ...")

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


def create_device(device, tenant):
    name = device["hostname"]
    if name is None:
        name = device["mac_addr"]
    # TODO
    payload = {
        "name": name,
        "role": 3,  # Ziskat predtym
        "device_type": 1,  # Ziskat predtym
        "site": 1,  # Ziskat predtym
        # "location": "", # Location, miestnost, napr: C603, ak neexistuje, vytvori sa v NetBoxe
        "status": device["status"],  # Je iny status neaktivny pre ip addr a pre device
        "tenant": tenant  # Zvoleny tenant pouzivatelom
    }

    device_ulr = f"{netbox_url}/api/dcim/devices/"

    try:
        response = requests.post(device_ulr, json=payload, headers=headers, timeout=5)
        if response.status_code == 201:
            device["id"] = response.json().get("id", [])
            print(f"Device {device['hostname']} with MAC Address {device['mac_addr']} added successfully.")
        else:
            print(f"Failed to add Device {device['hostname']} with MAC Address {device['mac_addr']}. ")
            print(f"{response.status_code} {response.text}")
        return device
    except requests.exceptions.ConnectionError:
        print("Connection error: The server might be down.")
    except requests.exceptions.Timeout:
        print("Connection timeout: The server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return exit(1)


def create_interface(device):
    if device["id"] is None:
        return

    payload = {
        "device": device["id"],
        "name": "eth0",
        "type": "other",  # Manualne nastavit
        "mac_address": device["mac_addr"],
    }

    interface_url = f"{netbox_url}/api/dcim/interfaces/"

    try:
        response = requests.post(interface_url, json=payload, headers=headers, timeout=5)
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
    payload = {
        "primary_ip4": device["ip_addr_id"]
    }

    device_url = f"{netbox_url}/api/dcim/devices/{device['id']}/"

    try:
        response = requests.patch(device_url, json=payload, headers=headers, timeout=5)
        if response.status_code == 200:
            print(f"Device with ID {device['id']} has been updated successfully with primary IP {device['ip_addr']}.")
        else:
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


def display_tenant_options(json_data):
    tenants = json_data.get("results", [])
    if not tenants:
        print("Permission denied. Contact administrator.")
        return exit(1)

    print("Available tenants:")
    for idx, tenant in enumerate(tenants):
        print(f"{idx}: {tenant['name']} - {tenant['description']}")

    while True:
        try:
            choice = int(input("Enter the number corresponding to your tenant: "))
            if 0 <= choice < len(tenants):
                selected_tenant = tenants[choice]
                return selected_tenant
            else:
                print("Invalid choice. Please enter a number within the range.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nOperation terminated by the user.")
            return exit(1)


def export_csv(hosts_metadata):
    default_output_name = "output"
    output_file_name = input("Enter output file name (press Enter for default): ")
    output = output_file_name if output_file_name else default_output_name

    if not output.endswith('.csv'):
        output += '.csv'

    headers = hosts_metadata[0].keys() if hosts_metadata else []

    try:
        with open(output, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerows(hosts_metadata)
    except Exception as e:
        print(f"An error occurred while writing to the file: {e}")
        return None

    print(f"File '{output}' was successfully created.")
    return output


def main():

    subnet = str(input("Enter the subnet with mask: "))

    devices = scan_subnet(subnet)
    print(json.dumps(devices, indent=4))

    check_config()
    tenants = find_available_tenants()
    tenant = display_tenant_options(tenants)

    for device in devices:
        device = create_device(device, tenant["id"])
        device = create_interface(device)
        device = create_address(device, tenant["id"])
        update_device(device)

    export_csv(devices)


if __name__ == "__main__":
    main()
