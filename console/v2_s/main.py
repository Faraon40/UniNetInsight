""""""

__author__ = "Antonio Kis"

import json
import subprocess
import sys
import platform
import ipaddress
import argparse
import yaml
import os
import xml.etree.ElementTree as etree
import socket


def load_config():
    """"""
    with open("../../configs/config.yml", 'r') as f:
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
    root = etree.fromstring(xml_data.stdout)

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
            "ip_addr": ip,
            "mac_addr": mac,
            "manufacturer": vendor,
            "status": "active" if status == "up" else "offline",
            "hostname": hostname,
        })

    return hosts


def main():
    """"""
    parser = argparse.ArgumentParser(description="Run Nmap ping scan on a given subnet.")
    parser.add_argument("-addr", "--address", help="Subnet in CIDR notation (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output", help="File to save the output (e.g., results.csv)")

    args = parser.parse_args()
    validate_config()

    # Prompt if address was not provided via CLI
    if not args.address:
        args.address = input("Enter subnet (CIDR notation, e.g. 192.168.1.0/24): ").strip()

    result = execute_nmap(subnet=args.address)
    hosts = parse_nmap_xml(result)


if __name__ == "__main__":
    main()
