# VMG3925-B10B
Root permissions on recent Zyxel firmware V5.13(AAVF.18)C0 for VMG3925-B10B Dual-Band Wireless AC/N VDSL2 Combo WAN Gigabit Gateway with USB

## Usage
```sh
% python3 getroot.py --destination 192.168.1.1:80 --username admin --password 1234
```
The output should look like:
```
Password for user "root" is "12abcd34"
Password for user "supervisor" is "12abcd34"
```

## Routers with operator firmware
If you have a router with a non-Zyxel firmware, you will not be able to flash the Zyxel firmware using the web interface. To change the firmware, use the instructions from [this](https://www.youtube.com/watch?v=TvOdtIMBXpY) video.