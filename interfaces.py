import subprocess

import netifaces


def get_interfaces() -> list:
    proc = subprocess.Popen(['ip', 'link', 'show'], stdout=subprocess.PIPE)
    output = proc.communicate()[0].decode()
    interfaces = []
    for line in output.split('\n'):
        if 'state UP' in line:
            interface = line.split(':')[1].strip()
            interfaces.append(interface)
    return interfaces


def get_gateway_ip() -> str:
    interfaces = netifaces.interfaces()

    priority_interface = None
    max_priority = -1
    for iface in interfaces:
        if iface.startswith("lo") or "addr" not in netifaces.ifaddresses(iface):
            continue

        priority = netifaces.ifaddresses(iface)[netifaces.AF_INET][0].get("priority", -1)

        if priority > max_priority:
            max_priority = priority
            priority_interface = iface

    router_ip = netifaces.gateways()["default"][netifaces.AF_INET][0]

    return router_ip