sudo modprobe can
sudo modprobe can-raw
sudo modprobe slcan
sudo slcand -o -c -s0 /dev/ttyACM0 slcan0
sudo ifconfig slcan0 up
sudo ifconfig slcan0 txqueuelen 1000

