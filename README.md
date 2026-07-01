# wardriver.py
A Python-based wardriving tool that scans for APs that are potentially insecure, such as WEP, OPEN or WPS v1.0
and logs to the console and sends a bleep when it finds one.

To make this work, the following dependencies must be met:
* Kali Linux 2026.1 or later (that's what was used to develop this tool)
* A Wi-Fi adapter that supports monitor mode (I like Alfa)
* Run as sudo and NOT root otherwise the audio notifications don't work!

* Install an audio application to send the beep through the speaker

_sudo apt-get install sox libsox-fmt-all_


---
## Run the following commands

First one kills off any services that will interfere with the operation of the Wi-Fi adapter

_sudo airmon-ng check kill_


Next put the adapter in monitor mode (change the wlan parameter to match your adapter)

_sudo airmon-ng start wlan0_


Next ensure that airodump-ng is running to ensure channel scanning is operational otherwise you'll miss some APs

_sudo airodump-ng wlan0mon --band abg_

---

## Usage 
And in a second terminal window....

_sudo python3 wardriver6.py -i wlan0mon -wps1 -open -wep_

The command-line parameters _-wps1, -open, -wep_ can be removed depending on your requirements.<br><br>



<img width="612" height="219" alt="image" src="https://github.com/user-attachments/assets/05810461-e008-44c8-b841-5012594b595b" />

```diff
! Example screenshot of the application in operation
```

