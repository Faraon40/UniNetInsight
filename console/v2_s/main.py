""""""

__author__ = "Antonio Kis"


import subprocess
import sys
import platform
import ipaddress
import argparse


def validate_subnet(subnet):
    """"""
    try:
        ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        print(f"Error: The provided subnet '{subnet}' is invalid or missing a subnet mask (e.g., /24).")
        sys.exit(1)


def execute_nmap(subnet, use_sudo=True, override_os=None):
    """"""
    validate_subnet(subnet)

    current_os = override_os if override_os else platform.system()

    if current_os == "Linux":
        command = ["nmap", "-sn", subnet]
        if use_sudo:
            command.insert(0, "sudo")
    elif current_os == "Windows":
        command = ["nmap", "-sn", subnet]
    else:
        print("Unsupported OS.")
        sys.exit(1)

    print(f"Scanning subnet: {subnet}")
    print(f"Command: {' '.join(command)}")

    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout


def main():
    """"""
    parser = argparse.ArgumentParser(description="Run Nmap ping scan on a given subnet.")
    parser.add_argument("-addr", "--address", help="Subnet in CIDR notation (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output", help="File to save the output (e.g., results.csv)")
    parser.add_argument("--os", choices=["Linux", "Windows"], help="Manually specify OS (for testing)")

    args = parser.parse_args()

    # Prompt if address was not provided via CLI
    if not args.address:
        args.address = input("Enter subnet (CIDR notation, e.g. 192.168.1.0/24): ").strip()


    result = execute_nmap(
        subnet=args.address,
        use_sudo=not args.no_sudo,
        override_os=args.os,
    )

    # Output to file if requested
    # if result and args.output:
    #     try:
    #         with open(args.output, "w") as f:
    #             f.write(result.stdout)
    #         print(f"Output saved to {args.output}")
    #     except Exception as e:
    #         print(f"Failed to write to output file: {e}")
    #         sys.exit(1)


if __name__ == "__main__":
    main()