#!/bin/bash

cp -n /etc/hosts{,.old}
newhn=$(cat /dev/urandom | tr -dc 'A-Z0-9' | head -c13)

echo "127.0.0.1    localhost" > /etc/hosts
echo "127.0.0.1    $newhn" >> /etc/hosts
echo "$newhn" > /etc/hostname

sleep 1

xhost +$newhn

sudo reboot now

exit