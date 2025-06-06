from scapy.all import sniff, IP, TCP, UDP
import logging
import subprocess

firewall_rules = {
    'block_ip': [],
    'block_port': [],
    'block_proto': []  # NOTE: Protocol blocking not handled by iptables in this demo
}

log_file = 'firewall_log.txt'
logging.basicConfig(filename=log_file, level=logging.INFO)

def add_iptables_rule(rule_type, value):
    try:
        if rule_type == 'block_ip':
            subprocess.run(["iptables", "-A", "INPUT", "-s", value, "-j", "DROP"], check=True)
        elif rule_type == 'block_port':
            subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(value), "-j", "DROP"], check=True)
    except subprocess.CalledProcessError:
        logging.error(f"[ERROR] Failed to add iptables rule for {rule_type}: {value}")

def remove_iptables_rule(rule_type, value):
    try:
        if rule_type == 'block_ip':
            subprocess.run(["iptables", "-D", "INPUT", "-s", value, "-j", "DROP"], check=True)
        elif rule_type == 'block_port':
            subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(value), "-j", "DROP"], check=True)
    except subprocess.CalledProcessError:
        logging.error(f"[ERROR] Failed to remove iptables rule for {rule_type}: {value}")

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        proto = packet[IP].proto
        protocol = 'TCP' if proto == 6 else 'UDP' if proto == 17 else 'OTHER'
        dport = None

        if TCP in packet:
            dport = packet[TCP].dport
        elif UDP in packet:
            dport = packet[UDP].dport

        if src_ip in firewall_rules['block_ip']:
            logging.info(f"[BLOCKED] IP: {src_ip}")
            return

        if dport and dport in firewall_rules['block_port']:
            logging.info(f"[BLOCKED] Port: {dport}")
            return

        if protocol in firewall_rules['block_proto']:
            logging.info(f"[BLOCKED] Protocol: {protocol}")
            return

        logging.info(f"[ALLOWED] {src_ip}:{dport} ({protocol})")

def start_sniffing():
    sniff(filter="ip", prn=packet_callback, store=0)
