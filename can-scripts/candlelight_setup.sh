sudo modprobe can
sudo modprobe vcan
sudo modprobe can-raw
sudo modprobe slcan
sudo ip link set can0 type can bitrate 500000
sudo ip link set dev can0 qlen 1000
sudo ip link set up can0

