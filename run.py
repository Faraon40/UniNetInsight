"""
This module implements automated scan and upload tool using API.

This module provides functions to manage and interact with network
devices and IP addresses using the NetBox API. It includes functionality
to retrieve device information, add new devices, update device
configurations, manage manufacturers, and export host data to
a CSV file.

Functions:
    - load_config: Loads the configuration from a YAML file or
     environment variables.
    - validate_config: Validates the configuration by checking for the
     required keys.
    - validate_subnet: Validates the provided subnet to ensure it is in
     a correct format.
    - get_hostname: Retrieves the hostname associated with a given IP
     address.
    - parse_nmap_xml: Parses Nmap XML output and extracts host
     information such as IP, MAC, and status.
    - get_from: Fetches data from a given URL using the GET method.
    - display_options: Displays available options from the API and
     prompts the user to select one.
    - create_devices: Creates new devices in the NetBox API based on
     provided host information.
    - create_interfaces: Creates interfaces for devices in the
     NetBox API.
    - create_addresses: Creates IP addresses for devices in the
     NetBox API.
    - update_devices: Updates device information in the NetBox API,
     such as the primary IP address.
    - create_manufacturers: Adds new manufacturers to the NetBox API
     if they do not already exist.
    - export_hosts_to_csv: Exports a list of hosts to a CSV file,
     with options to include or exclude IDs.

Module Usage:
    This module requires the configuration file `config.yml` to contain
     API tokens and base URL for the NetBox API. It also depends on the
     `requests` and `xml.etree.ElementTree` libraries for interacting
     with the API and parsing Nmap XML output.

    Example:
        config = load_config()
        validate_config()
        hosts = parse_nmap_xml(nmap_data)
        create_devices(hosts, tenant, config)
        export_hosts_to_csv(hosts, "hosts.csv")
"""

__author__ = "Antonio Kis"

import csv
import json
import shutil
from datetime import datetime
from ipaddress import ip_address

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
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_local_ips():
    """
    Retrieve a set of all local IPv4 addresses associated with the host.

    This function attempts to resolve the host's IPv4 addresses using
    two methods:
    1. It first adds the primary IP address obtained via
    `socket.gethostbyname()`.
    2. It then collects additional IPv4 addresses using
    `socket.getaddrinfo()`.

    Returns:
        set: A set of strings, each representing a unique local IPv4
        address.

    Notes:
        - Only IPv4 addresses (AF_INET) are returned.
        - Any resolution failures (e.g., hostname not resolvable) are
           silently ignored.
        - Duplicate addresses are automatically eliminated due to
           the use of a set.
    """
    local_ips = set()
    hostname = socket.gethostname()

    try:
        local_ips.add(socket.gethostbyname(hostname))
    except socket.gaierror:
        pass

    try:
        for info in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
            ip = info[4][0]
            local_ips.add(ip)
    except socket.gaierror:
        pass

    return local_ips


def post_to(url, payload, config, success_msg="", failure_msg=""):
    """
    Send a POST request with a JSON payload to a URL using an API token.

    Args:
        url (str): The target URL to which the POST request will
         be sent.
        payload (dict): The JSON-serializable data to be included in
         the request body.
        config (dict): Configuration dictionary containing at least
         the key `'api_token'`.
        success_msg (str, optional): Message to print upon a successful
         request (HTTP 201 Created).
        failure_msg (str, optional): Message to print if the request
         fails (non-201 response).

    Returns:
        dict or None: Parsed JSON response from the server if the
         request is successful (HTTP 201); otherwise, returns None
         if the request fails or encounters an exception.

    Notes:
        - This function disables SSL certificate verification
           (`verify=False`).
        - Connection errors, timeouts, and other request exceptions
           are caught and printed.
        - In case of failure, the HTTP status code and response
           body are printed.
    """
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
            verify=False,
            timeout=15
        )

        if response.status_code == 201:
            if success_msg:
                print(success_msg)
            return response.json()
        else:
            print(failure_msg)
            print(f"{response.status_code} {response.text}")

    except requests.exceptions.ConnectionError as conn_err:
        print("Connection error: The server might be unreachable.")
        print(f"Connection error: {conn_err}")
    except requests.exceptions.Timeout:
        print("Timeout: Server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

    return None


def load_config():
    """
    Load application configuration from a YAML file.

    This function reads the `configs/config.yml` file to extract
    required configuration values.
    It then checks for the presence of the `API_TOKEN` and `BASE_URL`
    environment variables, which take precedence over values specified
    in the configuration file.

    Returns:
        dict: A dictionary containing the configuration keys:
              - 'api_token' (str): API token for authentication.
              - 'base_url' (str): Base URL for API requests.

    Raises:
        FileNotFoundError: If the configuration file does not exist.
        yaml.YAMLError: If the YAML file is malformed and cannot be
         parsed.

    Notes:
        - This function assumes the YAML file contains keys 'api_token'
           and 'base_url'.
        - Environment variables are optional but will override
           corresponding YAML values if set.
    """
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
    """
    Validate the presence of required configuration keys.

    This function loads the configuration using `load_config()` and
    checks for the presence of required keys: 'api_token' and
    'base_url'. If any key is missing or empty, an error message is
    printed to `stderr`, and the program exits with a non-zero status.

    Returns:
        dict: The validated configuration dictionary containing all
        required keys.

    Side Effects:
        - Prints error messages to `sys.stderr` if validation fails.
        - Calls `sys.exit(1)` to terminate the program on missing keys.

    Raises:
        SystemExit: If one or more required configuration keys are
        missing.

    Notes:
        - Values can come from either `configs/config.yml` or
           corresponding environment variables.
        - This function ensures that the application will not proceed
           with incomplete configuration.
    """
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
    """
    Validate the provided IPv4 subnet.

    This function checks if the given subnet is a valid IPv4 network.
    It attempts to parse the subnet and verify its format. If the subnet
    is invalid or missing a subnet mask (e.g., `/24`), an error message
    is printed and the program is terminated with a non-zero exit code.

    Args:
        subnet (str): The subnet to be validated. This should be
         a string in the format "IP_address/subnet_mask"
         (e.g., "192.168.1.0/24").

    """
    try:
        ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        print(f"Error: The provided subnet '{subnet}' is invalid or missing"
              f" a subnet mask (e.g., /24).", file=sys.stderr)
        sys.exit(1)


def execute_nmap(subnet):
    """
    Validate that the provided subnet string is a valid IPv4 network.

    This function checks whether the given subnet is a valid IPv4
    network by attempting to construct an `ipaddress.IPv4Network`
    object with it.
    The `strict=False` parameter allows for non-network addresses (i.e.,
    host IPs with subnet masks).

    Args:
        subnet (str): The subnet string to validate,
         e.g., "192.168.1.0/24".

    Side Effects:
        - Prints an error message to `sys.stderr` if the subnet is
           invalid or missing a subnet mask.
        - Terminates the program by calling `sys.exit(1)` on
           invalid input.

    Raises:
        SystemExit: If the provided subnet is not valid.

    Example:
        validate_subnet("10.0.0.0/16")  # Valid
        validate_subnet("192.168.1.100")  # Invalid, missing subnet mask
    """
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
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
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
    """
    Resolve the hostname for a given IPv4 address.

    This function attempts a reverse DNS lookup to obtain the hostname
    associated with the specified IP address.

    Args:
        ip (str): The IPv4 address to resolve (e.g., "192.168.1.1").

    Returns:
        str or None: The resolved hostname if available; otherwise,
         `None` if the lookup fails (e.g., no reverse DNS entry or
         unreachable host).

    Raises:
        None explicitly. If the resolution fails, the function catches
        `socket.herror` and returns `None`.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None


def parse_nmap_xml(xml_data, default_vendor="Unspecified"):
    """
    Parse Nmap XML scan output and extract host information.

    This function processes the stdout of an Nmap scan in XML format and
    extracts relevant information for each discovered host, such as IP
    address, MAC address, vendor (manufacturer), and status (up or down)

    Args:
        xml_data (CompletedProcess): The result object from
        `subprocess.run()` or similar, which contains the Nmap XML
         output in `xml_data.stdout`.
        default_vendor (str, optional): Default manufacturer name to use
         if none is provided in the MAC address entry.
        Defaults to "Unspecified".

    Returns:
        list of dict: A list of dictionaries, each representing a
        discovered host, with the following keys:
            - 'id': None (placeholder, can be used for database
             integration)
            - 'interface_id': None (placeholder)
            - 'ip_addr_id': None (placeholder)
            - 'ip_addr': IP address of the host
            - 'mac_addr': MAC address of the host (if available)
            - 'manufacturer': Vendor name associated with MAC address
            - 'status': 'active' if host is up, otherwise 'offline'
            - 'hostname': Hostname resolved from IP address (currently
             left empty)

    Notes:
        - Only IPv4 and MAC addresses are parsed.
        - Hostname resolution is disabled by default; can be enabled
           with `get_hostname(ip)`.
        - Hosts without an IP address are skipped from meaningful
           reporting.
    """
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
    """
    Perform an authenticated GET request to a specified URL.

    This function sends an HTTP GET request to the provided URL
    using an API token for authorization, and returns the parsed
    JSON response if the request is successful (HTTP 200 OK).

    Args:
        url (str): The full URL to which the GET request will be
         sent.
        config (dict): A configuration dictionary that must contain:
            - 'api_token' (str): The token used for API
               authentication.

    Returns:
        dict or None: The parsed JSON response if the request is
         successful; otherwise, returns `None` and prints an error
         message.

    Side Effects:
        - Prints error messages to stdout if the response code is
          not 200 or if an exception occurs (connection error,
          timeout, etc.).

    Exceptions Handled:
        - `requests.exceptions.ConnectionError`: Server is
            unreachable.
        - `requests.exceptions.Timeout`: Request timed out.
        - `requests.exceptions.RequestException`: Any other
           request-related error.

    Notes:
        - SSL verification is disabled via `verify=False`. This is
           insecure and should be used with caution, especially in
           production environments.
        - Timeout for the request is fixed to 15 seconds.
    """
    headers = {
        "Authorization": f"Token {config['api_token']}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            url=url,
            headers=headers,
            verify=False,
            timeout=15,
        )

        if response.status_code == 200:
            return response.json()
        else:
            print(f"{response.status_code} {response.text}")

            return None
    except requests.exceptions.ConnectionError as conn_err:
        print("Connection error: The server might be down.")
        print(f"Connection error: {conn_err}")

    except requests.exceptions.Timeout:
        print("Connection timeout: The server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return None


def display_options(
        config, api_endpoint, name_field="option",
        description_field="description", label_name=None,
        allow_none=False, none_label="No selection"
):
    """
    Display a list of options retrieved from a NetBox API endpoint.

    Parameters:
        config (dict): Configuration with 'base_url' and 'api_token'.
        api_endpoint (str): The API endpoint to fetch data from.
        name_field (str): Field to display as name (default: "option").
        description_field (str): Field to display as description.
        label_name (str): Human-readable label to show in prompt.
        allow_none (bool): If True, allows selection of None option.
        none_label (str): Label to use for the "None" option if allowed.

    Returns:
        dict or None: Selected item dictionary or None if no selection.
    """
    url = f"{config['base_url']}{api_endpoint}"
    data = get_from(url, config)

    if not data or "results" not in data:
        print("Permission denied or no data found. Contact administrator.")
        sys.exit(1)

    entity_name = label_name or os.path.basename(api_endpoint.strip("/"))
    print(f"Available {entity_name}:")

    options = []
    if allow_none:
        print("0: " + none_label)
        options.append(None)

    for idx, item in enumerate(data["results"],
                               start=(1 if allow_none else 0)):
        name = item.get(name_field, "N/A")
        description = item.get(description_field)
        print(f"{idx}: {name}" + (f" - {description}" if description else ""))
        options.append(item)

    while True:
        try:
            choice = int(input(f"Enter a number corresponding to your"
                               f" {name_field}: "))
            print()
            if 0 <= choice < len(options):
                return options[choice]
            else:
                print("Invalid choice. Please enter a number"
                      " within the range.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nOperation terminated by the user.")
            sys.exit(1)


def display_tenants(config):
    """Display available tenant options, including 'No tenant'."""
    return display_options(
        config,
        api_endpoint="/api/tenancy/tenants/",
        name_field="name",
        description_field="description",
        label_name="tenants",
        allow_none=True,
        none_label="No tenant"
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


def create_devices(hosts, tenant, site, config):
    """
    Create device entries in NetBox for a list of discovered hosts.

    This function uses the provided configuration and tenant information
    to register each host in NetBox as a device. It prompts the user to
    select the site, device role and device type using interactive
    helper functions. Each host is posted to the NetBox API, and the
    resulting device ID is saved back into the corresponding host entry
    if creation succeeds.

    Args:
        hosts (list of dict): A list of discovered host dictionaries,
         each containing:
            - 'mac_addr' (str): MAC address of the host.
            - 'hostname' (str or None): Resolved hostname (maybe None).
            - 'status' (str): Operational status, e.g., "active" or
              "offline".
        tenant (dict): A dictionary representing the selected NetBox
        site: A location representing infrastructure.
         tenant, must contain:
            - 'id' (int): ID of the tenant.
        config (dict): Configuration dictionary with:
            - 'base_url' (str): Base URL of the NetBox API.
            - 'api_token' (str): Token used for authentication.

    Returns:
        list of dict: The original list of hosts, with each successfully
         created device
        having an additional "id" key set to the device ID returned by
         NetBox.

    """
    device_url = f"{config['base_url']}/api/dcim/devices/"

    print("How do you want to select device roles/types?")
    print("0: Same role/type for all devices")
    print("1: Different role/type per device")

    while True:
        try:
            role_mode = input("Enter choice [0/1]: ").strip()
            print()
            if role_mode in ["0", "1"]:
                break
            else:
                print("Invalid choice. Enter choice [0/1]:")
                print()
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nOperation terminated by the user.")
            sys.exit(1)

    ip_address_data = get_from(
        url=f"{config['base_url']}/api/ipam/ip-addresses/",
        config=config
    )

    existing_ips = set()
    existing_addr = ip_address_data.get("results", [])
    for addr in existing_addr:
        raw_ip = addr.get("address")
        if raw_ip:
            try:
                # Strip subnet mask, keep only the IP address
                ip = str(ipaddress.ip_interface(raw_ip).ip)
                existing_ips.add(ip)
            except ValueError:
                continue  # Skip malformed IPs

    # Compare scanned hosts
    new_hosts = []

    for host in hosts:
        ip = host.get("ip_addr")
        if ip in existing_ips:
            print(f"Device: {host['hostname'] or host['mac_addr']} | "
                  f"MAC: {host['mac_addr']} | "
                  f"Ip Address: {host['ip_addr']} already exists in Netbox.")
        else:
            new_hosts.append(host)

    hosts = new_hosts
    input("Press any key to continue: ").strip()
    print()

    if role_mode == '0':
        role = display_device_roles(config)
        dtype = display_device_types(config)
        for host in hosts:
            name = host.get("hostname") or host["mac_addr"]
            payload = {
                "name": name,
                "role": role["id"],
                "device_type": dtype["id"],
                "site": site["id"],
                "status": host["status"]
            }
            if tenant is not None:
                payload["tenant"] = tenant["id"]

            result = post_to(
                url=device_url,
                payload=payload,
                config=config,
                success_msg=f"Device '{name}' added "
                            f"(MAC: {host['mac_addr']}).",
                failure_msg=f"Failed to add device '{name}' "
                            f"(MAC: {host['mac_addr']})."
            )

            if result:
                host["id"] = result.get("id")

    else:
        for host in hosts:
            print(f"Assigning role/type for device: "
                  f"{host['ip_addr']} | "
                  f"MAC: {host['mac_addr']} | "
                  f"Manufacturer: {host['manufacturer']}")
            role = display_device_roles(config)
            dtype = display_device_types(config)

            name = host.get("hostname") or host["mac_addr"]
            payload = {
                "name": name,
                "role": role["id"],
                "device_type": dtype["id"],
                "site": site["id"],
                "status": host["status"]
            }
            if tenant is not None:
                payload["tenant"] = tenant["id"]

            result = post_to(
                url=device_url,
                payload=payload,
                config=config,
                success_msg=f"Device '{name}' added "
                            f"(MAC: {host['mac_addr']}).",
                failure_msg=f"Failed to add device '{name}' "
                            f"(MAC: {host['mac_addr']})."
            )

            if result:
                host["id"] = result.get("id")

    return hosts


def create_interfaces(hosts, config):
    """
    Create network interface entries in NetBox for a list of devices.

    This function registers a network interface (e.g., "eth0") for each
    device in the provided list of hosts. It uses the provided
    configuration to send POST requests to the NetBox API and adds an
    interface with the MAC address of each host. The resulting interface
    ID is added to the corresponding host dictionary.

    Args:
        hosts (list of dict): A list of host dictionaries, each
         containing:
            - 'id' (int): The device ID of the host in NetBox.
            - 'mac_addr' (str): The MAC address of the host.
            - 'hostname' (str): The hostname of the host (used for
             error messages).
        config (dict): Configuration dictionary containing:
            - 'base_url' (str): Base URL of the NetBox API.
            - 'api_token' (str): Token for authentication with NetBox.

    Returns:
        list of dict: The original list of hosts, with each successfully
         created interface
        having an additional "interface_id" key set to the interface ID
         returned by NetBox.

    """
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
    """
    Create IP address entries in NetBox for a list of devices.

    This function registers IP addresses for each device in the provided
    list of hosts. It uses the provided configuration and tenant
    information to create IP address entries in the NetBox IPAM
    (IP Address Management) system. The resulting IP address ID is added
    to the corresponding host dictionary.

    Args:
        hosts (list of dict): A list of host dictionaries,
        each containing:
            - 'ip_addr' (str): The IP address of the host.
            - 'interface_id' (int): The ID of the host's network
              interface.
            - 'mac_addr' (str): The MAC address of the host.
        tenant (dict): A dictionary representing the selected NetBox
        tenant, must contain:
            - 'id' (int): The ID of the tenant.
        config (dict): Configuration dictionary with:
            - 'base_url' (str): Base URL of the NetBox API.
            - 'api_token' (str): Token used for authentication.

    Returns:
        list of dict: The original list of hosts, with each successfully
         created IP address
        having an additional "ip_addr_id" key set to the IP address ID
         returned by NetBox.

    """
    ip_address_url = f"{config['base_url']}/api/ipam/ip-addresses/"

    for host in hosts:
        payload = {
            "address": f"{host['ip_addr']}/24",
            "status": "active",
            "description": host["mac_addr"],
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": host["interface_id"],
        }

        if tenant is not None:
            payload["tenant"] = tenant["id"]

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
    """
    Update device information in NetBox with the primary IP address.

    This function updates the 'primary_ip4' field for each device in the
    provided list of hosts. It sends a PATCH request to the NetBox API
    to set the primary IPv4 address for each device, based on the IP
    address ID in the host dictionary.

    Args:
        hosts (list of dict): A list of host dictionaries,
         each containing:
            - 'id' (int): The ID of the device in NetBox.
            - 'ip_addr_id' (int): The ID of the IP address to be set as
             the primary IP.
            - 'ip_addr' (str): The IP address to be associated with the
             device.
        config (dict): Configuration dictionary with:
            - 'base_url' (str): Base URL of the NetBox API.
            - 'api_token' (str): Token used for authentication.

    """
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
                verify=False,
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


def create_manufacturers(hosts, config):
    """
    Create new manufacturers in NetBox that don't already have an entry.

    This function extracts unique manufacturers from the list of hosts
    and checks if they already exist in the NetBox database. If a
    manufacturer doesn't exist, it creates a new manufacturer entry in
    the NetBox system.

    Args:
        hosts (list of dict): A list of host dictionaries, each
         containing a 'manufacturer' key representing the device's
         manufacturer name.
        config (dict): Configuration dictionary with:
            - 'base_url' (str): The base URL of the NetBox API.
            - 'api_token' (str): Token used for authentication.

    """
    manufacturer_url = f"{config['base_url']}/api/dcim/manufacturers/"
    new_manufacturers = set(host["manufacturer"] for host in hosts)
    manufacturers_data = get_from(
        f"{config['base_url']}/api/dcim/manufacturers/", config
    )
    existing_manufacturers = {
        manufacturer["name"].lower() for manufacturer in
                              manufacturers_data.get("results", [])
    }

    for manufacturer in new_manufacturers:
        if manufacturer.lower() in existing_manufacturers:
            continue
        manufacturer = manufacturer.lower()
        manufacturer = manufacturer.replace(" ", "-")
        manufacturer = manufacturer.replace("(", "-")
        manufacturer = manufacturer.replace(")", "-")
        manufacturer = manufacturer.replace(".", "-")
        manufacturer = manufacturer.replace("/", "-")

        payload = {
            "name": manufacturer,
            "slug": manufacturer
        }

        post_to(
            url=manufacturer_url,
            payload=payload,
            config=config,
            success_msg=f"New Manufacturer {manufacturer} added."
        )


def export_hosts_to_csv(hosts, filename, include_ids=False):
    """
    Export a list of host dictionaries to a CSV file.

    This function takes a list of hosts and exports the relevant details
    of each host to a CSV file. The user can choose whether to include
    IDs (such as device ID, interface ID, and IP address ID) in the CSV
    export.

    Args:
        hosts (list of dict): A list of host dictionaries, where each
         dictionary contains information about a host such as IP
         address, MAC address, manufacturer, status, and hostname.
        filename (str): The name of the CSV file to export the host data
         to. If the filename contains any relative paths like `../`,
         they will be stripped to ensure the file is created in the
         project folder.
        include_ids (bool): If True, the export will include 'id',
         'interface_id', and 'ip_addr_id'. If False, the export will
          exclude these fields.

    Returns:
        None: The function does not return any value. It writes to a
         CSV file.
    """
    # Sanitize the filename to ensure it's always created in the
    # project folder
    # Strip any directory components (e.g., ../, /etc/)
    # Create the file in the current working directory
    filename = os.path.basename(filename)
    filename = os.path.join(os.getcwd(), filename)

    # Define fields based on the user's choice
    if include_ids:
        fieldnames = ["id", "interface_id", "ip_addr_id", "ip_addr",
                      "mac_addr", "manufacturer", "status", "hostname"]
    else:
        fieldnames = ["ip_addr", "mac_addr", "manufacturer",
                      "status", "hostname"]

    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for host in hosts:
                writer.writerow({k: host.get(k, "") for k in fieldnames})
        print(f"Hosts exported to CSV: {filename}")
    except Exception as e:
        print(f"Error exporting to CSV: {e}")


def main():
    """Execute the main code."""
    parser = argparse.ArgumentParser(description="Run Nmap ping scan on a"
                                                 " given subnet.")
    parser.add_argument("-addr", "--address",
                        help="Subnet in CIDR notation (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output",
                        help="File to save the output (e.g., results)")

    args = parser.parse_args()
    config = validate_config()
    selected_hosts = []

    # Prompt if address was not provided via CLI
    if not args.address:
        args.address = input("Enter subnet (CIDR notation, "
                             "e.g. 192.168.1.0/24): ").strip()

    result = execute_nmap(subnet=args.address)
    hosts = parse_nmap_xml(result)
    local_ips = get_local_ips()

    # Identify which hosts match local device
    local_hosts = [host for host in hosts if host['ip_addr'] in local_ips]

    if local_hosts:
        print("Your scanning device was detected in the scan.")
        include_self = input("Do you want to include your own device in the"
                             " results? [y/N]: ").strip().lower()
        if include_self != 'y':
            hosts = [
                host for host in hosts if host['ip_addr'] not in local_ips
            ]

    print(json.dumps(hosts, indent=4))

    # Ask user if or how they want to upload to NetBox
    print("\nChoose how to upload scanned devices to NetBox:")
    print("0: Do not upload")
    print("1: Upload all devices")
    print("2: Select devices individually")

    while True:
        try:
            upload_mode = input("Enter choice [0/1/2]: ").strip()
            print()
            if upload_mode in ["0", "1", "2"]:
                break
            else:
                print("Invalid choice. Enter choice [0/1/2]:")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nOperation terminated by the user.")
            sys.exit(1)

    if upload_mode == '0':
        pass
    elif upload_mode == '1':
        selected_hosts = hosts
    elif upload_mode == '2':
        selected_hosts = []

        for host in hosts:
            print(f"Device: {host['ip_addr']} | "
                  f"MAC: {host['mac_addr']} | "
                  f"Manufacturer: {host['manufacturer']}")
            choice = input("Do you want to upload this device to NetBox? "
                           "[y/N]: ").strip().lower()
            print()
            if choice == 'y':
                selected_hosts.append(host)
    else:
        print("Invalid input. Skipping upload.")
        selected_hosts = []

    if upload_mode in ['1', '2']:
        tenant = display_tenants(config)
        site = display_sites(config)
        create_manufacturers(selected_hosts, config)
        selected_hosts = create_devices(selected_hosts, tenant, site, config)
        selected_hosts = create_interfaces(selected_hosts, config)
        selected_hosts = create_addresses(selected_hosts, tenant, config)
        update_devices(selected_hosts, config)

    # Ask user if or how they want to export
    print("\nDo you want to export scan results to CSV?")
    print("0: Do not export any devices")
    print("1: Export all scanned devices")
    print("2: Export only devices selected for NetBox upload")

    while True:
        try:
            export_choice = input("Enter choice [0/1/2]: ").strip()
            print()
            if export_choice in ["0", "1", "2"]:
                break
            else:
                print("Invalid choice. Enter choice [0/1/2]: ")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nOperation terminated by the user.")
            sys.exit(1)

    if export_choice in ['1', '2']:
        include_ids_choice = input("Include NetBox-assigned IDs in export? "
                                   "[y/N]: ").strip().lower()
        include_ids = include_ids_choice == 'y'

        # Prompt for output filename if not given in CLI
        if not args.output:
            filename = input("Enter output filename "
                             "(press Enter to use default): ").strip()
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"output_{timestamp}.csv"
            elif not filename.lower().endswith('.csv'):
                filename += '.csv'
            args.output = filename

        if export_choice == '1':
            export_data = hosts
        else:
            if not selected_hosts:
                print("\nNo devices were uploaded, "
                      "so there is nothing to export.")
                return
            export_data = selected_hosts
        export_hosts_to_csv(export_data, args.output, include_ids=include_ids)


if __name__ == "__main__":
    main()
