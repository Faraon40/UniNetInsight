""""""

__author__ = "Antonio Kis"

import json
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


def post_to(url, payload, config, success_msg="", failure_msg=""):
    """"""
    headers = {
        "Authorization": f"Token {config['api_token']}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        response = requests.post(
            url=url,
            json=payload,
            headers=headers,
            timeout=15
        )

        if response.status_code == 201:
            if success_msg:
                print(success_msg)
            return response.json()
        else:
            print(failure_msg)
            print(f"{response.status_code} {response.text}")

    except requests.exceptions.ConnectionError:
        print("Connection error: The server might be unreachable.")
    except requests.exceptions.Timeout:
        print("Timeout: Server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

    return None


def load_config():
    """"""
    config_path = "configs/config.yml"
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"The configuration file '{config_path}' "
                                f"does not exist.")

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    return {
        "api_token": os.getenv("API_TOKEN", config["api_token"]),
        "base_url": os.getenv("BASE_URL", config["base_url"])
    }


def validate_config():
    """"""
    required_keys = ["api_token", "base_url"]
    config = load_config()
    missing = [key for key in required_keys if not config.get(key)]

    if missing:
        print("Configuration Error:", end=" ", file=sys.stderr)
        for key in missing:
            print(f"Missing '{key}' in config.yaml or environment variables.",
                  file=sys.stderr)
        print("Cannot proceed. Please set the required configuration values.",
              file=sys.stderr)
        sys.exit(1)
    return config


def validate_subnet(subnet):
    """"""
    try:
        ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        print(f"Error: The provided subnet '{subnet}' is invalid or missing"
              f" a subnet mask (e.g., /24).", file=sys.stderr)
        sys.exit(1)


def execute_nmap(subnet):
    """"""
    validate_subnet(subnet)

    # Check if nmap is installed
    if not shutil.which("nmap"):
        print("Error: 'nmap' is not installed or not in your system's PATH.")
        print("Please install Nmap and try again.")
        sys.exit(1)

    current_os = platform.system()
    command = ["nmap", "-sn", "-oX", "-", subnet]

    if current_os == "Linux":
        command.insert(0, "sudo")
    elif current_os == "Darwin":  # macOS
        command.insert(0, "sudo")
    elif current_os == "Windows":
        pass
    else:
        print(f"Unsupported operating system: {current_os}")
        sys.exit(1)

    print(f"Scanning subnet {subnet} ...")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result
    except subprocess.CalledProcessError as e:
        print("Error: Nmap execution failed.")
        print(f"Return code: {e.returncode}")
        print(f"Output: {e.output}")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: Nmap not found. Ensure it is installed and accessible.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
        sys.exit(1)


def get_hostname(ip):
    """"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None


def parse_nmap_xml(xml_data, default_vendor="Unspecified"):
    """"""
    hosts = []
    root = ETree.fromstring(xml_data.stdout)

    for host in root.findall("host"):
        status = host.find("status").attrib.get("state", "unknown")
        ip = ""
        mac = ""
        vendor = default_vendor
        hostname = ""

        for addr in host.findall("address"):
            if addr.attrib["addrtype"] == "ipv4":
                ip = addr.attrib["addr"]
                hostname = get_hostname(ip)
            elif addr.attrib["addrtype"] == "mac":
                mac = addr.attrib["addr"]
                vendor = addr.attrib.get("vendor", default_vendor)

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


def get_from(url, config):
    """Fetch data from the given URL."""
    headers = {
        "Authorization": f"Token {config['api_token']}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            url=url,
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:
            return response.json()
        else:
            print(f"{response.status_code} {response.text}")
            return None
    except requests.exceptions.ConnectionError:
        print("Connection error: The server might be down.")
    except requests.exceptions.Timeout:
        print("Connection timeout: The server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return None


def display_options(config, api_endpoint, name_field="option", description_field="description", label_name=None):
    """General function to display options and return the selected option."""
    url = f"{config['base_url']}{api_endpoint}"
    data = get_from(url, config)

    if not data or "results" not in data:
        print("Permission denied or no data found. Contact administrator.")
        return sys.exit(1)

    entity_name = label_name or os.path.basename(api_endpoint.strip("/"))
    print(f"Available {entity_name}:")
    for idx, item in enumerate(data["results"]):
        name = item.get(name_field, "N/A")
        description = item.get(description_field)
        print(f"{idx}: {name}" + (f" - {description}" if description else ""))

    while True:
        try:
            choice = int(input(f"Enter a number corresponding to your {name_field}: "))
            print()
            if 0 <= choice < len(data["results"]):
                return data["results"][choice]
            else:
                print("Invalid choice. Please enter a number within the range.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nOperation terminated by the user.")
            sys.exit(1)


def display_tenants(config):
    """Display available tenant options."""
    return display_options(
        config,
        api_endpoint="/api/tenancy/tenants/",
        name_field="name",
        description_field="description",
        label_name="tenants"
    )


def display_device_roles(config):
    """Display device roles options."""
    return display_options(
        config,
        api_endpoint="/api/dcim/device-roles/",
        name_field="name",
        description_field="description",
        label_name="Device Roles"
    )


def display_device_types(config):
    """Display device types options."""
    return display_options(
        config,
        api_endpoint="/api/dcim/device-types/",
        name_field="display",
        description_field="description",
        label_name="Device Types"
    )


def display_sites(config):
    """Display sites options."""
    return display_options(
        config,
        api_endpoint="/api/dcim/sites/",
        name_field="name",
        description_field="description",
        label_name="Sites"
    )


def create_devices(hosts, tenant, config):
    """"""
    device_url = f"{config['base_url']}/api/dcim/devices/"

    # Bulc role
    # Bulc device_type
    # Bulc site
    for host in hosts:
        name = host.get("hostname") or host["mac_addr"]

        payload = {
            "name": name,
            "role": 17,  # school 1, home 17
            "device_type": 9,  # school 1, home 9
            "site": 4,  # school 1, home 4-9
            "status": host["status"],
            "tenant": tenant["id"]
        }

        result = post_to(
            url=device_url,
            payload=payload,
            config=config,
            success_msg=f"Device '{name}' added (MAC: {host['mac_addr']}).",
            failure_msg=f"Failed to add device '{name}' "
                        f"(MAC: {host['mac_addr']})."
        )

        if result:
            host["id"] = result.get("id")

    return hosts


def create_interfaces(hosts, config):
    """"""
    interface_url = f"{config['base_url']}/api/dcim/interfaces/"

    for host in hosts:
        payload = {
            "device": host["id"],
            "name": "eth0",
            "type": "other",
            "mac_address": host["mac_addr"],
        }

        result = post_to(
            url=interface_url,
            payload=payload,
            config=config,
            success_msg=f"Interface for Device {host['id']} added.",
            failure_msg=f"Failed to add interface for Device "
                        f"{host['hostname']}."
        )

        if result:
            host["interface_id"] = result.get("id")

    return hosts


def create_addresses(hosts, tenant, config):
    """"""
    ip_address_url = f"{config['base_url']}/api/ipam/ip-addresses/"

    for host in hosts:
        payload = {
            "address": f"{host['ip_addr']}/24",
            "status": "active",
            "tenant": tenant["id"],
            "description": host["mac_addr"],
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": host["interface_id"],
        }

        result = post_to(
            url=ip_address_url,
            payload=payload,
            config=config,
            success_msg=f"IP Address {host['ip_addr']} added.",
            failure_msg=f"Failed to add IP Address {host['ip_addr']}."
        )

        if result:
            host["ip_addr_id"] = result.get("id")

    return hosts


def update_devices(hosts, config):
    """"""
    headers = {
        "Authorization": f"Token {config['api_token']}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    for host in hosts:
        payload = {
            "primary_ip4": host["ip_addr_id"]
        }
        device_url = f"{config['base_url']}/api/dcim/devices/{host['id']}/"
        try:
            response = requests.patch(
                url=device_url,
                json=payload,
                headers=headers,
                timeout=15
            )
            if response.status_code == 200:
                print(f"Device with ID {host['id']} has been updated"
                      f" successfully with primary IP {host['ip_addr']}.")
            else:
                print(f"Failed to update device with ID {host['id']}.")
                print(f"{response.status_code} {response.text}")

        except requests.exceptions.ConnectionError:
            print("Connection error: The server might be down.")
            break
        except requests.exceptions.Timeout:
            print("Connection timeout: The server took too long to respond.")
            break
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            break


def get_manufacturers(config):
    manufacturer_url = f"{config['base_url']}/api/dcim/manufacturers/"

    headers = {
        "Authorization": f"Token {config['api_token']}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            url=manufacturer_url,
            headers=headers,
            timeout=15
        )
        if response.status_code == 200:
            manufacturer_data = response.json()
            return manufacturer_data

    except requests.exceptions.ConnectionError:
        print("Connection error: The server might be down.")
    except requests.exceptions.Timeout:
        print("Connection timeout: The server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return sys.exit(1)


def create_manufacturers(hosts, config):
    """"""
    manufacturer_url = f"{config['base_url']}/api/dcim/manufacturers/"

    headers = {
        "Authorization": f"Token {config['api_token']}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    new_manufacturers = set(host["manufacturer"] for host in hosts)

    manufacturers_data = get_manufacturers(config)
    existing_manufacturers = {manufacturer["name"].lower() for manufacturer in
                              manufacturers_data.get("results", [])}

    for manufacturer in new_manufacturers:
        if manufacturer.lower() in existing_manufacturers:
            continue
        payload = {
            "name": manufacturer,
            "slug": manufacturer.lower().replace(" ", "-")
        }

        try:
            response = requests.post(
                url=manufacturer_url,
                json=payload,
                headers=headers,
                timeout=15
            )
            if response.status_code == 201:
                print(f"Manufacturer '{manufacturer}' was successfully"
                      f" created.")

        except requests.exceptions.ConnectionError:
            print("Connection error: The server might be down.")
            break
        except requests.exceptions.Timeout:
            print("Connection timeout: The server took too long to respond.")
            break
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            break


def main():
    """"""
    parser = argparse.ArgumentParser(description="Run Nmap ping scan on a"
                                                 " given subnet.")
    parser.add_argument("-addr", "--address",
                        help="Subnet in CIDR notation (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output",
                        help="File to save the output (e.g., results.csv)")

    args = parser.parse_args()
    config = validate_config()

    # Prompt if address was not provided via CLI
    if not args.address:
        args.address = input("Enter subnet (CIDR notation, "
                             "e.g. 192.168.1.0/24): ").strip()

    result = execute_nmap(subnet=args.address)
    hosts = parse_nmap_xml(result)

    print(json.dumps(hosts, indent=4))
    tenant = display_tenant_options(config)
    create_manufacturers(hosts, config)
    hosts = create_devices(hosts, tenant, config)
    hosts = create_interfaces(hosts, config)
    hosts = create_addresses(hosts, tenant, config)
    update_devices(hosts, config)


if __name__ == "__main__":
    main()
