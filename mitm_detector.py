import os
import logging
import subprocess
from threading import Thread

import notify2
from scapy.all import *
from banner import show_banner
from interfaces import get_interfaces, get_gateway_ip


logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='mitm_detector.log',
    filemode='a'
)

def send_notification(title: str, message: str) -> None:
    subprocess.run(["notify-send", title, message])


class DetectorMITMAttack:
   
    def __init__(self, interface: str, target_ip: str) -> None:
        self.interface = interface
        self.target_ip = target_ip

    def block_mac_address(self, mac_address: str) -> None:
        logging.info(f"Blocking MAC address: {mac_address}")
        fw_command = subprocess.Popen('which iptables', shell=True, stdout=subprocess.PIPE)
        fw_type = fw_command.stdout.read().decode('utf-8').strip()
        
        if fw_type:
            command = f"sudo iptables -A INPUT -m mac --mac-source {mac_address} -j DROP"
        else:
            command = f"sudo nft add rule ip filter input ether saddr {mac_address} drop"
        
        subprocess.Popen(command, shell=True)
        logging.info(f"Executed command: {command}")

    def is_mitm_attack(self, packet: Packet) -> bool:
        if packet.haslayer(ARP):
            arp_packet = packet[ARP]

            if arp_packet.pdst != self.target_ip:
                return None

            if arp_packet.op == 2 and arp_packet.hwsrc != arp_packet.hwdst:
                warn_message = (
                    f"[ATTENTION] Potential MITM attack detected: "
                    f"{arp_packet.hwsrc} ({arp_packet.psrc}) -> "
                    f"{arp_packet.hwdst} ({arp_packet.pdst})"
                )
                print(f"\033[1;32m{warn_message}\033[0m")
                
                send_notification("MITM Detector", warn_message)
                logging.warning(warn_message)

                self.block_mac_address(arp_packet.hwsrc)
                return True

        return None

    def start_sniffing(self) -> None:
        print(f"\033[1;32m[INFO] Starting packet capture on interface {self.interface}\033[0m")
        logging.info(f"Starting packet capture on interface {self.interface}")
        
        try:
            sniff(iface=self.interface, prn=self.is_mitm_attack)
        except Exception as e:
            logging.error(f"Error while sniffing: {e}")
            print(f"\033[1;31m[ERROR] Sniffing failed: {e}\033[0m")

def start_mitm_detection(interface: str, target_ip: str) -> None:
    if interface not in get_interfaces():
        print("\033[1;31m[ERROR] Specified network interface not found\033[0m")
        return
    
    mitm = DetectorMITMAttack(interface, target_ip)
    thread = Thread(target=mitm.start_sniffing)
    thread.start()

def main() -> None:
    show_banner()
    interfaces = get_interfaces()
    default_gateway_ip = get_gateway_ip()

    print("Choose an option:")
    print("1. Enter network interface manually")
    print(f"2. Run on all network devices (Detected: {len(interfaces)}): {interfaces}")

    choice = input("\033[1;32m~# \033[0m")

    if choice == '1':
        interface = input("\nEnter the name of the network interface (e.g., wlan0): ")
        start_mitm_detection(interface, default_gateway_ip)
    elif choice == '2':
        for interface in interfaces:
            start_mitm_detection(interface, default_gateway_ip)
    else:
        print("\033[1;31m[ERROR] Invalid choice\033[0m")

if __name__ == '__main__':
    main()
