#!/bin/bash

sudo ifconfig eth0 down
sudo ifconfig wlan0 down

sleep 1

sudo systemctl stop NetworkManager

sleep 1

sudo macchanger -r eth0
sudo macchanger -r wlan0

sudo systemctl start NetworkManager

sleep 1

sudo ifconfig eth0 up
sudo ifconfig wlan0 up

exit