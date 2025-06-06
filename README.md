Python Network Firewall with iptables Integration
Overview

This project implements a basic network firewall using Python, integrating packet inspection with scapy and active blocking through Linux’s iptables. It features a simple Flask web interface to manage firewall rules dynamically.
Features

    Packet Sniffing: Uses scapy to monitor incoming IP packets in real time.

    Dynamic Rule Management: Add or remove firewall rules via a user-friendly Flask web interface.

    Rule Types Supported:

        Block by IP address

        Block by TCP port

        (Protocol blocking monitored but not actively blocked via iptables in this version)

    Active Blocking: Automatically adds/removes iptables rules to block traffic at the OS kernel level.

    Logging: All allowed and blocked traffic events are logged to a file (firewall_log.txt).

Requirements

    Linux operating system

    Root or sudo privileges (required for packet sniffing and managing iptables)

    Python 3.x

    Python packages:

        scapy

        flask

Install Python packages with:

pip3 install scapy flask

Usage

    Run the Flask firewall application as root:

sudo python3 firewall_app.py

    Open your browser and navigate to: http://localhost:5005

    Add or remove firewall rules dynamically:

        Block specific IP addresses (e.g., 192.168.1.100)

        Block TCP ports (e.g., 22 for SSH)

    The firewall automatically applies iptables rules to block matching traffic at the system level.

    Traffic events are logged in firewall_log.txt.

Important Notes

    Root Access: Packet sniffing and iptables management require running the app with sudo/root.

    Caution: Blocking critical IPs or ports (like your SSH port 22) can disrupt your network connection.

    iptables Cleanup: To remove all firewall rules added by this app, run:

sudo iptables -F

    Currently, protocol blocking is monitored but not enforced at the iptables level.

Potential Extensions

    Real-time traffic log viewer in the web UI

    Persistence of rules across restarts (e.g., save/load from file or database)

    Support for UDP and ICMP blocking

    More granular control over iptables rules (ranges, interfaces, logging)

License

This project is open source and free to use under the MIT License.
