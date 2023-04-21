#!/bin/bash

dell_array=("F8:DB:88" "F8:CA:B8" "F8:BC:12" "F8:B1:56" "F4:8E:38" "F0:4D:A2" "F0:1F:AF" "EC:F4:BB" "E4:F0:04" "E0:DB:55" "E0:D8:48" "D8:9E:F3" "D4:BE:D9" "D4:AE:52" "D4:81:D7" "D0:94:66" "D0:67:E5" "D0:43:1E" "C8:1F:66" "BC:30:5B" "B8:CA:3A" "B8:AC:6F" "B8:2A:72" "B4:E1:0F" "B0:83:FE" "A4:BA:DB" "A4:4C:C8" "A4:1F:72" "98:90:96" "98:40:BB" "90:B1:1C" "8C:EC:4B" "8C:CF:09" "84:8F:69" "84:7B:EB" "84:2B:2B" "80:18:44" "7C:C9:5A" "78:45:C4" "78:2B:CB" "74:E6:E2" "74:86:7A" "64:00:6A" "5C:F9:DD" "5C:26:0A" "58:8A:5A" "54:9F:35" "50:9A:4C" "4C:76:25" "48:4D:7E" "44:A8:42" "40:5C:FD" "34:E6:D7" "34:17:EB" "28:F1:0E" "24:B6:FD" "24:6E:96" "20:47:47" "20:04:0F" "1C:40:24" "18:FB:7B" "18:DB:F2" "18:A9:9B" "18:66:DA" "18:03:73" "14:FE:B5" "14:B3:1F" "14:9E:CF" "14:18:77" "10:98:36" "10:7D:1A" "08:00:1B" "00:C0:4F" "00:B0:D0" "00:60:48" "00:26:B9" "00:25:64" "00:24:E8" "00:23:AE" "00:22:19" "00:21:9B" "00:21:70" "00:1E:C9" "00:1E:4F" "00:1D:09" "00:1C:23" "00:1A:A0" "00:19:B9" "00:18:8B" "00:16:F0" "00:15:C5" "00:15:30" "00:14:22" "00:13:72" "00:12:48" "00:12:3F" "00:11:43" "00:0F:1F" "00:0D:56" "00:0B:DB" "00:08:74" "00:06:5B" "00:01:44" "00:00:97")
RANDOM=$$$(date +%s)
selectedMAC=${dell_array[$RANDOM % ${#dell_array[@]} ]}
#echo "Vendor MAC: $selectedMAC"

hexchars="0123456789ABCDEF"
end=$( for i in {1..6} ; do echo -n ${hexchars:$(( $RANDOM % 16 )):1} ; done | sed -e 's/\(..\)/:\1/g' )
completeMAC=$selectedMAC$end
echo "New MAC (eth0): $completeMAC"

end=$( for i in {1..6} ; do echo -n ${hexchars:$(( $RANDOM % 16 )):1} ; done | sed -e 's/\(..\)/:\1/g' )
completeMAC2=$selectedMAC$end
echo "New MAC (wlan0): $completeMAC2"

sudo ifconfig eth0 down
sudo ifconfig wlan0 down

sleep 1

sudo systemctl stop NetworkManager

sleep 1

sudo macchanger -m $completeMAC eth0
sudo macchanger -m $completeMAC wlan0

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
