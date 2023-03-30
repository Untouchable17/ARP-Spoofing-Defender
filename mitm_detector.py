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

def send_notification(title, message):
    subprocess.run(["notify-send", title, message])


class DetectorMITMAttack:
   
    def __init__(self, interface: str, target_ip: str) -> None:
        self.interface = interface
        self.target_ip = target_ip

    def block_mac_address(self, mac_address: str) -> None:
        fw_command = subprocess.Popen('which iptables', shell=True, stdout=subprocess.PIPE)
        fw_type = fw_command.stdout.read().decode('utf-8').strip()
        if fw_type:
            command = f"sudo iptables -A INPUT -m mac --mac-source {mac_address} -j DROP"
        else:
            command = f"sudo nft add rule ip filter input ether saddr {mac_address} drop"
        subprocess.Popen(command, shell=True)

    def is_mitm_attack(self, packet: Packet) -> bool:
        if packet.haslayer(ARP):
            arp_packet = packet[ARP]

            if arp_packet.pdst != self.target_ip:
                return False

            if arp_packet.op == 2 and arp_packet.hwsrc != arp_packet.hwdst:
                print(f"\033[1;32m\033[1;32m[ATTENTION]\033[91m Потенциальная MITM-атака обнаружена: \033[91m{arp_packet.hwsrc} ({arp_packet.psrc}) -> \033[1;32m\033[1;32m{arp_packet.hwdst} ({arp_packet.pdst})\033[0m")

                warn_message = f"Обнаружена MITM-атака: {arp_packet.hwsrc} ({arp_packet.psrc}) -> {arp_packet.hwdst} ({arp_packet.pdst})"
                send_notification(
                    "MITM Detector", 
                    warn_message
                )
                logging.warning(warn_message)

                self.block_mac_address(arp_packet.hwsrc)
                return True

        return

    def start_sniffing(self) -> None:
        print(f"\033[1;32m\033[1;32m[INFO]\033[91m\033[91m Запуск захвата пакетов на интерфейсе\033[0m {self.interface}")
        logging.info(f"Запуск захвата пакетов на интерфейсе {self.interface}")
        sniff(iface=self.interface, prn=self.is_mitm_attack)


def start_mitm_detection(interface, target_ip):
    if interface not in get_interfaces():
        print("\033[1;32m[ERROR]\033[1;31m Указанный сетевой интерфейс не найден\033[0m")
        return False
    mitm = DetectorMITMAttack(interface, target_ip)
    thread = Thread(target=mitm.start_sniffing)
    thread.start()


def main():
    show_banner()
    interfaces = get_interfaces()
    default_gateway_ip = get_gateway_ip()

    print("Выберите вариант запуска")
    print("1. Ввести сетевой интерфейс вручную")
    print(f"2. Запуск на все сетевые устройства \033[1;32m\033[1;32m(Обнаружены ({len(interfaces)}): {interfaces})\033[1;37m\033[1;37m")

    choice = input("\033[1;32m\033[1;32m~# \033[1;37m\033[1;37m")

    if choice == '1':
        print("\nВведите имя сетевого интерфейса: (например wlan0)")
        interface = input("\033[1;32m\033[1;32m~# \033[1;37m\033[1;37m")
        start_mitm_detection(interface, default_gateway_ip)
    elif choice == '2':
        interfaces = get_interfaces()
        for interface in interfaces:
            start_mitm_detection(interface, default_gateway_ip)
    else:
        print("\033[1;32m[ERROR]\033[1;31m Неверный выбор\033[0m")
        return False

if __name__ == '__main__':
    main()
