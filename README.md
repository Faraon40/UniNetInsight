# UniNetInsight Team Project

Author: _Faraon40_

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Features](#features)
- [Installation](#installation)
- [Usage Guide](#usage)


## Overview

This project is implementation of a cli network scanning tool with NetBox 
compatibility that allows scanning a subnet, gathering device information 
(IP Address, MAC Address, Hostname (if available)) and importing them into
NetBox database.

In this README we will instruct you how to set up the program to properly scan and upload
data to a remote NetBox server. 

This project is currently in its early development phase. 
It may not yet cover all possible edge cases, scenarios, or challenges 
that could emerge in real-world applications.

Our goal was to implement an automated network scanning system that uses
existing methods to identify active hosts, and gather basic information
about the devices present in the network.


## Project Structure

    UniNetInsight
        ├── configs
            └── config.yml
        ├── .gitattributes
        ├── .gitignore
        ├── pyproject.toml
        ├── README.md
        ├── requirements.txt 
        └── run.py 


## Features

- Automated Network Scanning
- Device Discovery via Command `nmap`
- NetBox Integration
- Script for Updating NetBox via its API


## About `nmap`

`nmap` (Network Mapper) is an open-source tool used for network discovery and 
security auditing. It is commonly used by system administrators and developers 
to scan local or remote networks to identify active devices, their IP addresses,
MAC addresses, open ports, and other network characteristics.

### How it works in our project.

```
nmap -sn -Ox - <subnet>
```

* -sn: Ping scan - detects which host are up (no port scan)
* -oX - Outputs the scan result in XML format to stdout
* <subnet>: The target network block to scan (e.g. 192.168.1.0/24)


## Installation

### Requirements

- Python 3.10+
- NetBox (v4.1.4)
- Linux Distribution (Ubuntu 22.04 or newer) for NetBox
- Windows/Linux for Network Scanning Tool (UniNetIsight)

### Steps

To properly install NetBox we recommend to follow [NetBox Installation Guide](https://netboxlabs.com/docs/netbox/en/stable/installation/3-netbox/).
This guide is enough to run NetBox locally on your machine and be able to run UniNetInsight locally.

### 1. Clone the Repository

```bash
git clone https://github.com/Faraon40/UniNetInsight
cd UniNetInsight
```

### 2. Set Up Python Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```
If you don't have `pip`, install it first.

### 4. Install System Dependencies (If Required)

#### Ubuntu/Debian:
```bash
sudo apt install nmap
```

#### macOS (with Homebrew):
```bash
brew install nmap
```


## Usage


### Set up `api_token` and `base_url` in `config.yml` of your running NetBox.

1. Log in to NetBox.
2. Naviage to you Profile and click "API Tokens" tab.
3. Click "Add" to generate a new token and copy the token when it appears.
4. Edit `configs/config.yml` and paste your token


```yaml
api_token: 123456789abcdefg
base_url: localhost:8000
```


### Run

```bash
python run.py
```


