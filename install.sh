#!/bin/bash


function python_packages(){
	echo "[*] Installing python packages.."
	python -m venv venv
	source venv/bin/activate
	pip install -r requirements.txt
	echo "[*] Installed successfully!"
}

function linux_packages(){
	echo "[*] Installing linux packages.."
	apt install libnotify-bin
	pkill -HUP notification-daemon
	echo "[*] Installed successfully!"
}


if [ "$EUID" -ne 0 ]; then
  echo "Run script as root"
  exit
else
  if [ ! -d "venv" ] || ! cmp -s requirements.txt venv/requirements.txt; then
    python_packages
    linux_packages
  fi
fi