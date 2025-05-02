# Uni-Net-Insight Team Project

Author: Antonio Kiš

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [Docker Deployment (Optional)](#docker-deployment-optional)
- [Known Issues](#known-issues)
- [Future Work](#future-work)
- [License](#license)

## Overview

This project is implementation of a network scanning tool with NetBox 
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

## Features

- Automated network scanning
- Device discovery via command `nmap`
- NetBox integration
- Custom scripts for updating NetBox via its API

## Installation

### Requirements

- Python 3.10+
- NetBox (v4.9)
- Linux Distribution (Ubuntu 22.04 or newer) for NetBox
- Windows/Linux for Network Scanning Tool (UniNetIsight)
- `requests`, `nmap` or `python-nmap` module

### Steps

To properly install NetBox we recommend to follow [NetBox Installation Guide](https://netboxlabs.com/docs/netbox/en/stable/installation/3-netbox/).
This guide is enough to run NetBox locally on your machine and be able to run UniNetIsight locally.

1. Download source code from [here](https://github.com/Faraon40/UniNetInsight).
2. Inside the configs/ directory, create a file named `config.yml` with the following contents:



    api_token: 1234567890abcdefg
    base_url: http://localhost:8000



3. Generate the API token in NetBox
- Log in to your NetBox instance as a Super Admin.
- Navigate to Admin > API Tokens.
- Create a new token with write permissions.
- Copy the generated token and paste it into the `api_token` field in `config.yml`.