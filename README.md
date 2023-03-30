<h1 align="center">
    <a href="https://github.com/Untouchable17/ARP Spoofing Defender">
        <img src="https://ibb.co/7tgkqpX" width="700">
    </a>
</h1>

<p align="center">
<a href="https://github.com/Untouchable17/Cam-Hackers"><img src="https://img.shields.io/static/v1?label=version&message=1.0.0&color=red"></a>
<a href="https://github.com/Untouchable17/Cam-Hackers/issues?q=is:issue+is:closed"><img src="https://img.shields.io/github/issues-closed/Untouchable17/Cam-Hackers?color=orange"></a>
</p>

<h1 align="center">ARP Spoofing Defender</h1>

<b>ARP Spoofing Defender</b> is a project designed to protect local networks from ARP Spoofing attacks. ARP Spoofing is a type of network attack in which an attacker sends fake ARP packets to intercept network traffic. ARP Spoofing Defender provides mechanisms to detect such attacks and protect the network from them. The project includes tools for attack detection, protection mechanisms, as well as instructions and guides for users. ARP Spoofing Defender is a reliable and effective solution for protecting local networks from ARP Spoofing attacks.
# Documentation

Installing and using script Installation process:

<h3>Execute all commands on behalf of the superuser</h3>
> Method 1: Fast Download

1. Downloading or cloning this github repository.
```
git clone https://github.com/Untouchable17/ARP-Spoofing-Defender
```
2. Make the file executable with the chmod +x command
```
chmod +x install.sh
sudo bash install.sh or sudo ./install.sh
```
<br/>
3. Run one of the scripts you need

```
- Defender: sudo python mitm_detector.py
- ARP-Attack: sudo python arp_spoofing.py <target_ip> <gateway_ip> <target_mac> <gateway_mac> <interval (default 2>

Launch example:
sudo python mitm_detector.py (then follow the instructions after starting)
sudo python arp_spoofing.py 192.168.1.2 192.168.1.1 08:00:27:ff:ff:ff 08:00:27:aa:aa:aa --interval 2
```

> Method 2: Manual Download
1. Downloading or cloning this GitHub repository.
```
git clone https://github.com/Untouchable17/ARP-Spoofing-Defender
```
2. Create and activate python virtual env
```
python3 -m venv venv
source venv/bin/activate
```
3. Install all requirements
```
pip3 install -r requirements.txt
```
4. Install Linux Package
```
apt install libnotify-bin
pkill -HUP notification-daemon
```
4. Run scripts as shown above


# Contact Developer


    Telegram:           @secdet17
    Group:              t.me/secdet_team
    Email:              tylerblackout17@gmail.com

