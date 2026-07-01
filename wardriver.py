#!/usr/bin/env python3

# Wardriver for  scanning for WEP, OPN and WPS 1.0 Wi-Fi Access Points
# Written by F1lby July 2026
# Excuse my bad coding - I'm not a coder so this is a best endeavour !
# See Github for licensing

# Dependencies
# Kali 2026.1 (was built & tested in that version of Distro) 
#
# apt-get install sox libsox-fmt-all

# Wi-Fi adapter in monitor mode (better using an Alfa adapter)
# sudo airmon-ng check kill
# sudo airmon-ng start wlan0 (choose your favourite Wi-Fi adapter)

# Always run this script as sudo and not root otherwise audio beep notifications don't work
#
# **IMPORTANT STUFF - Make sure sudo airodump-ng wlan1mon --band abg is running in a separate Window
# to stimulate the Wi-Fi adapter to make use of all channels!

# command line usage  sudo python3 wardriver4.py -i wlan1mon -wps1 -open -wep


# We need to import some libaries needed to make this thing work

import argparse
import sys
import struct
import os
import pwd
from scapy.all import *

# This tool remembers already discovered networks so as to stop too many console notifications & beeps!
# Note, if another network of the same SSID is found later on, it won't alert you!
# And thats a limitation. You can always edit that bit out if it annoys you.

seen_macs = set()

def trigger_audio_alert(essid, bssid, trigger_reason):
    """Log the triggeing details & play a sound bypassing sudo barriers."""
#     print(f"\n[ALERT] AP Triggered by '{essid}' ({bssid}) -> Reason: {trigger_reason}")
# Sounds don't seem to run as sudo so have to find the real user and run sound
# genration in a lower privilege state. This is a bit of a hack.
    try:
        real_user = os.getenv("SUDO_USER")
        if real_user and real_user != "root":
            # Extract UID to bypass XDG runtime bridge
            user_id = pwd.getpwnam(real_user).pw_uid
            cmd = (
                f"sudo -u {real_user} "
                f"XDG_RUNTIME_DIR=/run/user/{user_id} "
                f"PULSE_SERVER=unix:/run/user/{user_id}/pulse/native "
                f"play -n synth 0.3 sine 1000 > /dev/null 2>&1 &"
            )
        else:
            cmd = "play -n synth 0.3 sine 1000 > /dev/null 2>&1 &"
        os.system(cmd)
    except Exception:
        pass

def parse_wps(pkt):
    """Parses Vendor Specific Elements to detect if WPS 1.0 or 2.0 is present."""
    elt = pkt[Dot11Elt]
    while isinstance(elt, Dot11Elt):
        if elt.ID == 221 and len(elt.info) >= 4:
            if elt.info[0:4] == b'\x00\x50\xf2\x04':
                wps_data = elt.info[4:]
                idx = 0
                while idx < len(wps_data) - 4:
                    attr_type = struct.unpack(">H", wps_data[idx:idx+2])[0]
                    attr_len = struct.unpack(">H", wps_data[idx+2:idx+4])[0]
                    attr_val = wps_data[idx+4:idx+4+attr_len]
                    if attr_type == 0x104a and len(attr_val) >= 1:
                        version_hex = attr_val[0]
                        if version_hex == 0x10:
                            return "1.0"
                        elif version_hex == 0x20:
                            return "2.0"
                    idx += 4 + attr_len
        elt = elt.payload
    return "None"

def make_packet_handler(args):
    """Returns a packet handler closure configured with user preferences."""
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt[Dot11].addr3
            if bssid in seen_macs:
                return
            try:
                essid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                if not essid.strip():
                    essid = "<Hidden Network>"
            except:
                essid = "<Unknown>"
            capability = pkt[Dot11Beacon].cap if pkt.haslayer(Dot11Beacon) else pkt[Dot11ProbeResp].cap
            is_encrypted = capability.privacy
            has_rsn = pkt.haslayer(Dot11EltRSN) or any(isinstance(e, Dot11Elt) and e.ID == 48 for e in pkt.layers())
            has_wpa = any(isinstance(e, Dot11Elt) and e.ID == 221 and e.info.startswith(b'\x00\x50\xf2\x01') for e in pkt.layers())
            sec_type = "WPA/WPA2+"
            if not is_encrypted:
                sec_type = "OPN"
            elif is_encrypted and not has_rsn and not has_wpa:
                sec_type = "WEP"
            wps_version = parse_wps(pkt)
            match_found = False
            triggers = []

            if args.open and sec_type == "OPN":
                match_found = True
                triggers.append("OPN")
            if args.wep and sec_type == "WEP":
                match_found = True
                triggers.append("WEP")
            if args.wps1 and wps_version == "1.0":
                match_found = True
                triggers.append("WPS 1.0")
            if match_found:
                seen_macs.add(bssid)
                print(f"{essid:<25} {bssid:<20} {sec_type:<15} {wps_version:<10}")
                trigger_reason = " & ".join(triggers) if triggers else sec_type
                trigger_audio_alert(essid, bssid, trigger_reason)
    return packet_handler

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wireless Scanner")
    parser.add_argument("-i", "--interface", required=True, help="Wi-Fi interface in Monitor Mode")
    parser.add_argument("-open", action="store_true", dest="open", help="Scan for Open (OPN) APs")
    parser.add_argument("-wep", action="store_true", dest="wep", help="Scan for WEP APs")
    parser.add_argument("-wps1", action="store_true", dest="wps1", help="Scan for APs with WPS v1.0")

    args = parser.parse_args()
    if not (args.open or args.wep or args.wps1):
        args.open = True
        args.wep = True
        args.wps1 = True

    print(f"[*] Monitoring interface: {args.interface}")
    print(f"[*] Filters active -> Open: {args.open}, WEP: {args.wep}, WPS 1.0: {args.wps1}")
    print("-" * 75)
    print(f"{'ESSID':<25} {'BSSID':<20} {'SECURITY TYPE':<15} {'WPS VERSION':<10}")
    print("-" * 75)
    try:
        sniff(iface=args.interface, prn=make_packet_handler(args), store=0)
    except KeyboardInterrupt:
        print("\n[*] Scanner stopped. Mae fy llong hofran yn llawn llysywod")
        sys.exit(0)
# End of code - Mae fy llong hofran yn llawn llysywod
