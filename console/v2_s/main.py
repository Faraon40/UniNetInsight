""""""

__author__ = "Antonio Kis"

import json
from asyncio import timeout

import requests
import subprocess
import sys
import platform
import ipaddress
import argparse
import yaml
import os
import xml.etree.ElementTree as ETree
import socket


def load_config():
    """"""
    config_path = "../../configs/config.yml"
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    return {
        "api_token": os.getenv("API_TOKEN", config["api_token"]),
        "base_url": os.getenv("BASE_URL", config["base_url"])
    }


def validate_config():
    required_keys = ["api_token", "base_url"]
    config = load_config()
    missing = [key for key in required_keys if not config.get(key)]

    if missing:
        print("Configuration Error:", end=" ", file=sys.stderr)
        for key in missing:
            print(f"Missing '{key}' in config.yaml or environment variables.", file=sys.stderr)
        print("Cannot proceed. Please set the required configuration values.", file=sys.stderr)
        sys.exit(1)
    return config


def validate_subnet(subnet):
    """"""
    try:
        ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        print(f"Error: The provided subnet '{subnet}' is invalid or missing a subnet mask (e.g., /24).", file=sys.stderr)
        sys.exit(1)


def execute_nmap(subnet):
    """"""
    validate_subnet(subnet)

    current_os = platform.system()

    command = ["nmap", "-sn", "-oX", "-", subnet]
    if current_os == "Linux":
        command.insert(0, "sudo")
    elif current_os == "Windows":
        pass
    else:
        print("Unsupported OS.")
        sys.exit(1)

    print(f"Scanning subnet {subnet} ...")

    result = subprocess.run(command, capture_output=True, text=True)
    return result


def get_hostname(ip):
    """"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None


def parse_nmap_xml(xml_data):
    """"""
    hosts = []
    root = ETree.fromstring(xml_data.stdout)

    for host in root.findall("host"):
        status = host.find("status").attrib.get("state", "unknown")
        ip = ""
        mac = ""
        vendor = "Unspecified"
        hostname = ""

        for addr in host.findall("address"):
            if addr.attrib["addrtype"] == "ipv4":
                ip = addr.attrib["addr"]
                hostname = get_hostname(ip)
            elif addr.attrib["addrtype"] == "mac":
                mac = addr.attrib["addr"]
                vendor = addr.attrib.get("vendor", "Unspecified")

        hosts.append({
            "id": None,
            "interface_id": None,
            "ip_addr_id": None,
            "ip_addr": ip,
            "mac_addr": mac,
            "manufacturer": vendor,
            "status": "active" if status == "up" else "offline",
            "hostname": hostname,
        })
    return hosts


def get_tenants(config):
    tenant_url = f"{config['base_url']}/api/tenancy/tenants/"

    headers = {
        "Authorization": f"Token {config['api_token']}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            url=tenant_url,
            headers=headers,
            timeout=5
        )

        if response.status_code == 200:
            tenant_data = response.json()
            if "detail" in tenant_data and tenant_data["detail"] == "Invalid token.":
                print("Error: Invalid token. Please check your authentication.")
            elif "count" in tenant_data and tenant_data["count"] == 0:
                print("Permission denied. Contact administrator.")
            else:
                return tenant_data
    except requests.exceptions.ConnectionError:
        print("Connection error: The server might be down.")
    except requests.exceptions.Timeout:
        print("Connection timeout: The server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return sys.exit(1)


def display_tenant_options(config):
    tenant_data = get_tenants(config)
    tenants = tenant_data.get("results", [])
    if not tenants:
        print("Permission denied. Contact administrator.")
        return sys.exit(1)

    print("Available tenants:")
    for idx, tenant in enumerate(tenants):
        print(f"{idx}: {tenant['name'] - {tenant['description']}}")

    while True:
        try:
            choice = int(input("Enter a number corresponding to your tenant: "))
            if 0 <= choice < len(tenants):
                selected_option = tenants[choice]
                return selected_option
            else:
                print("Invalid choice. Please enter a number within the range.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nOperation terminated by the user.")
            sys.exit(1)


def create_devices(hosts, tenant, config):
    device_url = f"{config['base_url']}/api/dcim/devices/"

    headers = {
        "Authorization": f"Token {config['api_token']}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    for host in hosts:
        name = host.get("hostname") or host["mac_addr"]

        payload = {
            "name": name,
            "device_role": 1,
            "device_type": 1,
            "site": 1,
            "status": host["status"],
            "tenant": tenant["id"]
        }

        try:
            response = requests.post(
                url=device_url,
                json=payload,
                headers=headers,
                timeout=5
            )

            if response.status_code == 201:
                host["id"] = response.json().get("id", [])
                print(f"Device '{name}' added (MAC: {host['mac_addr']}, ID: {host['id']}).")
            else:
                print(f"Failed to add device '{name}' (MAC: {host['mac_addr']}).")
                print(f"{response.status_code} {response.text}")

        except requests.exceptions.ConnectionError:
            print("Connection error: The server might be unreachable.")
            break
        except requests.exceptions.Timeout:
            print("Timeout: Server took too long to respond.")
            break
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            break

    return hosts


def create_interfaces(hosts, tenant, config):
    interface_url = f"{config['base_url']}/api/dcim/interfaces/"

    headers = {
        "Authorization": f"Token {config['api_token']}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    for host in hosts:
        payload = {
            "device": host["id"],
            "name": "eth0",
            "type": "other",  # Manualne nastavit
            "mac_address": host["mac_addr"],
        }

        try:
            response = requests.post(
                url=interface_url,
                json=payload,
                headers=headers,
                timeout=5
            )

            if response.status_code == 201:
                host["interface_id"] = response.json().get("id", [])
                print(f"Interface of a Device {host['id']} with "
                      f"{host['interface_id']} added successfully.")
            else:
                print(f"Failed to add Interface of a Device {host['hostname']}")
                print(f"{response.status_code} {response.text}")

        except requests.exceptions.ConnectionError:
            print("Connection error: The server might be unreachable.")
            break
        except requests.exceptions.Timeout:
            print("Timeout: Server took too long to respond.")
            break
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            break

    return hosts


def create_addresses(hosts, tenant, config):
    ip_address_url = f"{config['base_url']}/api/ipam/ip-addresses/"

    headers = {
        "Authorization": f"Token {config['api_token']}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    return hosts


def main():
    """"""
    parser = argparse.ArgumentParser(description="Run Nmap ping scan on a given subnet.")
    parser.add_argument("-addr", "--address", help="Subnet in CIDR notation (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output", help="File to save the output (e.g., results.csv)")

    args = parser.parse_args()
    config = validate_config()

    # Prompt if address was not provided via CLI
    if not args.address:
        args.address = input("Enter subnet (CIDR notation, e.g. 192.168.1.0/24): ").strip()

    result = execute_nmap(subnet=args.address)
    hosts = parse_nmap_xml(result)

    tenant = display_tenant_options(config)
    hosts = create_devices(hosts, tenant, config)
    hosts = create_interfaces(hosts, tenant, config)
    hosts = create_addresses(hosts, tenant, config)


if __name__ == "__main__":
    main()
