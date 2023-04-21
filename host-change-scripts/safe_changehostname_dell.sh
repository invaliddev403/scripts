#!/bin/bash

sudo ifconfig eth0 down
sudo ifconfig wlan0 down

sleep 1

sudo systemctl stop NetworkManager

sleep 1

cp -n /etc/hosts{,.old}
newhnpre="WGC11"
newhnend=$(cat /dev/urandom | tr -dc 'A-Z0-9' | head -c8)
newhn=$newhnpre$newhnend
echo "$newhn"

echo "127.0.0.1    localhost" > /etc/hosts
echo "127.0.0.1    $newhn" >> /etc/hosts
echo "$newhn" > /etc/hostname

sleep 5

sudo reboot now

exit