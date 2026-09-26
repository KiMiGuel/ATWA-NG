#!/usr/bin/env python3
"""
EAPOL Packet Handler for WiFi 4-Way Handshake Analysis
Requires: scapy
Install: pip install scapy
"""

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from datetime import datetime
import threading
import time
import subprocess
import re
import os
import sys

# ANSI Color Codes for 1337 output
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Regular colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'


def strip_ansi(s):
    """Strip ANSI escape codes to get the true visible length of a string."""
    return re.sub(r'\033\[[0-9;]*m', '', s)


def ansi_ljust(s, width):
    """Left-justify a string that contains ANSI codes to the given visual width."""
    visible_len = len(strip_ansi(s))
    return s + ' ' * max(0, width - visible_len)


def box_row(content, width, lborder='║', rborder='║'):
    """Render a box row, padding content to visual width with correct right border."""
    return f"{lborder}{ansi_ljust(content, width)}{rborder}"


class HandshakeSession:
    """Stores the 4-way handshake messages for a specific AP-Client pair."""

    def __init__(self, ap_mac, client_mac):
        self.ap_mac = ap_mac
        self.client_mac = client_mac
        self.messages = {}  # {message_number: packet}
        self.timestamps = {}  # {message_number: timestamp}
        self.first_seen = datetime.now()
        self.last_updated = datetime.now()
        self.anonce = None
        self.snonce = None
        self.mic = None
        self.ssid = None

    def add_message(self, message_num, packet):
        """Add a handshake message to this session."""
        self.messages[message_num] = packet
        self.timestamps[message_num] = datetime.now()
        self.last_updated = datetime.now()

    def has_message(self, message_num):
        """Check if we have captured a specific message."""
        return message_num in self.messages

    def is_complete(self):
        """Check if we have all 4 messages of the handshake."""
        return all(i in self.messages for i in [1, 2, 3, 4])

    def get_progress(self):
        """Return a string showing which messages have been captured."""
        captured = [str(i) for i in range(1, 5) if i in self.messages]
        return f"[{', '.join(captured)}]" if captured else "[]"

    def __repr__(self):
        return f"HandshakeSession(AP={self.ap_mac}, Client={self.client_mac}, Messages={self.get_progress()})"


# Global dictionary to store handshakes: {(ap_mac, client_mac): HandshakeSession}
handshake_sessions = {}

# Global dictionary to store SSIDs by BSSID: {bssid: (ssid, beacon_packet)}
ssid_cache = {}

# Global flag for channel hopping thread
stop_channel_hopping = False


def print_banner():
    """Print sick ASCII art banner"""
    W = 55  # inner box visual width
    r1 = f"  {Colors.YELLOW}WiFi 4-Way Handshake Capture & Analysis Tool{Colors.GREEN}  "
    r2 = f"  {Colors.MAGENTA}[ Automated Channel Hopping Edition ]{Colors.GREEN}"
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ███████╗ █████╗ ██████╗  ██████╗ ██╗         ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
    ██╔════╝██╔══██╗██╔══██╗██╔═══██╗██║         ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    █████╗  ███████║██████╔╝██║   ██║██║         ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██╔══╝  ██╔══██║██╔═══╝ ██║   ██║██║         ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ███████╗██║  ██║██║     ╚██████╔╝███████╗    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Colors.RESET}
{Colors.GREEN}                    ╔{'═'*W}╗
                    {box_row(r1, W)}
                    {box_row(r2, W)}
                    ╚{'═'*W}╝{Colors.RESET}
    """
    print(banner)


def get_or_create_session(ap_mac, client_mac):
    """Get existing handshake session or create a new one."""
    key = (ap_mac.lower(), client_mac.lower())
    if key not in handshake_sessions:
        handshake_sessions[key] = HandshakeSession(ap_mac, client_mac)
    return handshake_sessions[key]


def extract_nonce(packet):
    """
    Extract the nonce (ANonce or SNonce) from an EAPOL packet.

    Returns:
        bytes: 32-byte nonce or None
    """
    raw_data = get_raw_data(packet)
    if raw_data is None:
        return None

    try:
        eapol_offset = find_eapol_offset(raw_data)
        if eapol_offset is None or len(raw_data) < eapol_offset + 49:
            return None

        # EAPOL Key frame structure after EAPOL header:
        # Descriptor Type (1) + Key Info (2) + Key Length (2) + Replay Counter (8) = 13
        # Then Key Nonce at offset 13 (relative to key descriptor, which starts at offset 4 from EAPOL)
        # So from EAPOL start: 4 + 13 = 17 (but eapol_offset already points past the EAPOL header)
        # Actually: eapol_offset points to EAPOL version, so:
        # Version(1) + Type(1) + Length(2) + Descriptor Type(1) + Key Info(2) + Key Length(2) + Replay Counter(8) = 17
        nonce_offset = eapol_offset + 17
        nonce = raw_data[nonce_offset:nonce_offset + 32]

        # Check if nonce is non-zero
        if nonce == b'\x00' * 32:
            return None

        return nonce if len(nonce) == 32 else None
    except Exception:
        return None


def extract_mic(packet):
    """
    Extract the MIC (Message Integrity Code) from an EAPOL packet.
    Handles different key descriptor versions (WPA/WPA2).

    Returns:
        bytes: 16-byte MIC or None
    """
    raw_data = get_raw_data(packet)
    if raw_data is None:
        return None

    try:
        eapol_offset = find_eapol_offset(raw_data)
        if eapol_offset is None or len(raw_data) < eapol_offset + 97:
            return None

        # EAPOL Key frame structure:
        # Version(1) + Type(1) + Length(2) + Descriptor Type(1) + Key Info(2) +
        # Key Length(2) + Replay Counter(8) + Key Nonce(32) + Key IV(16) +
        # Key RSC(8) + Reserved(8) = 81 bytes
        # Then MIC starts at offset 81
        mic_offset = eapol_offset + 81

        # MIC length depends on key descriptor version:
        # Version 1 (WPA): 16 bytes (HMAC-MD5)
        # Version 2 (WPA2): 16 bytes (HMAC-SHA1-128)
        # Version 3 (WPA2): 16 bytes (AES-128-CMAC)
        mic_length = 16

        mic = raw_data[mic_offset:mic_offset + mic_length]

        # Check if MIC is non-zero (zero MIC means no MIC present)
        if mic == b'\x00' * mic_length:
            return None

        return mic if len(mic) == mic_length else None
    except Exception:
        return None


def extract_ssid_from_beacon(packet):
    """
    Extract SSID from a beacon or probe response frame.

    Returns:
        str: SSID or None
    """
    if not packet.haslayer(Dot11Beacon) and not packet.haslayer(Dot11):
        return None

    try:
        # Look for the SSID information element
        if packet.haslayer(Dot11Elt):
            ssid = None
            # Iterate through information elements
            elt = packet[Dot11Elt]
            while elt:
                # ID 0 is SSID
                if elt.ID == 0 and elt.len > 0:
                    ssid = elt.info.decode('utf-8', errors='ignore')
                    break
                elt = elt.payload.getlayer(Dot11Elt)
            return ssid
    except Exception:
        pass

    return None


def handle_beacon_frame(packet):
    """
    Process beacon frames to extract and cache SSIDs.

    Args:
        packet: Scapy packet object
    """
    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]

    # Beacon frames have type 0, subtype 8
    if dot11.type != 0:
        return

    bssid = dot11.addr3 if dot11.addr3 else None
    if not bssid:
        return

    # Extract SSID
    ssid = extract_ssid_from_beacon(packet)
    if ssid:
        # Cache the SSID and beacon packet
        ssid_cache[bssid.lower()] = (ssid, packet)


def get_ssid_for_bssid(bssid):
    """
    Retrieve cached SSID for a given BSSID.

    Args:
        bssid: AP MAC address

    Returns:
        str: SSID or None
    """
    cached = ssid_cache.get(bssid.lower())
    return cached[0] if cached else None


def get_beacon_for_bssid(bssid):
    """
    Retrieve cached beacon packet for a given BSSID.

    Args:
        bssid: AP MAC address

    Returns:
        packet: Beacon packet or None
    """
    cached = ssid_cache.get(bssid.lower())
    return cached[1] if cached else None


def save_handshake_to_pcap(session, filename=None):
    """
    Save a complete handshake session to a PCAP file.
    Includes a beacon frame if available (required for cracking tools).

    Args:
        session: HandshakeSession object
        filename: Optional output filename (auto-generated if not provided)

    Returns:
        str: Path to the saved PCAP file
    """
    if not session.is_complete():
        return None

    if filename is None:
        # Auto-generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ap_clean = session.ap_mac.replace(':', '')
        filename = f"handshake_{ap_clean}_{timestamp}.pcap"

    # Collect all packets - start with beacon if available
    packets = []

    # Add beacon frame first (contains SSID, helpful for cracking tools)
    beacon = get_beacon_for_bssid(session.ap_mac)
    if beacon:
        packets.append(beacon)

    # Add handshake messages in order
    packets.extend([session.messages[i] for i in [1, 2, 3, 4] if i in session.messages])

    # Write to PCAP file
    try:
        wrpcap(filename, packets)

        # Verify the file was written
        if os.path.exists(filename):
            file_size = os.path.getsize(filename)
            print(f"{Colors.CYAN}    PCAP file size:{Colors.RESET} {Colors.GREEN}{file_size} bytes{Colors.RESET}")

            # Verify we can read it back
            try:
                test_read = rdpcap(filename)
                print(f"{Colors.CYAN}    PCAP contains:{Colors.RESET} {Colors.GREEN}{len(test_read)} packets{Colors.RESET}")
                expected_msg = f"{len(packets)} packets (beacon + 4 EAPOL messages)" if beacon else f"{len(packets)} packets (4 EAPOL messages)"
                print(f"{Colors.CYAN}    Expected:{Colors.RESET} {Colors.GREEN}{expected_msg}{Colors.RESET}")

                if len(test_read) != len(packets):
                    print(f"{Colors.YELLOW}    ⚠️  Warning: Packet count mismatch!{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.YELLOW}    ⚠️  Warning: Could not verify PCAP file: {e}{Colors.RESET}")

        return filename
    except Exception as e:
        print(f"Error writing PCAP file: {e}")
        return None


def extract_handshake_data(session):
    """
    Extract key cryptographic data from a complete handshake session.

    Args:
        session: HandshakeSession object

    Returns:
        bool: True if extraction was successful
    """
    if not session.is_complete():
        return False

    try:
        # Extract ANonce from Message 1
        if 1 in session.messages:
            session.anonce = extract_nonce(session.messages[1])

        # Extract SNonce from Message 2
        if 2 in session.messages:
            session.snonce = extract_nonce(session.messages[2])

        # Extract MIC from Message 2 (preferred) or Message 4
        if 2 in session.messages:
            session.mic = extract_mic(session.messages[2])
        elif 4 in session.messages and session.mic is None:
            session.mic = extract_mic(session.messages[4])

        # Get SSID from cache if available
        if not session.ssid:
            session.ssid = get_ssid_for_bssid(session.ap_mac)

        return True
    except Exception as e:
        print(f"Error extracting handshake data: {e}")
        return False


def verify_handshake_quality(session):
    """
    Verify the quality and completeness of captured handshake data.

    Args:
        session: HandshakeSession object

    Returns:
        tuple: (is_valid, warnings)
    """
    warnings = []
    is_valid = True

    # Check if all 4 messages present
    if not session.is_complete():
        warnings.append("Missing handshake messages")
        is_valid = False

    # Check ANonce
    if not session.anonce or session.anonce == b'\x00' * 32:
        warnings.append("ANonce is missing or zero")
        is_valid = False

    # Check SNonce
    if not session.snonce or session.snonce == b'\x00' * 32:
        warnings.append("SNonce is missing or zero")
        is_valid = False

    # Check MIC
    if not session.mic or session.mic == b'\x00' * 16:
        warnings.append("MIC is missing or zero")
        is_valid = False

    # Check if nonces are different
    if session.anonce and session.snonce and session.anonce == session.snonce:
        warnings.append("ANonce and SNonce are identical (should be different)")
        is_valid = False

    # Check SSID
    if not session.ssid:
        warnings.append("SSID not captured (required for cracking)")
        is_valid = False

    return is_valid, warnings


def print_raw_eapol_data(session):
    """
    Print raw EAPOL frame data for debugging.

    Args:
        session: HandshakeSession object
    """
    print("\n" + "="*70)
    print("RAW EAPOL DATA (for debugging)")
    print("="*70)

    for msg_num in [1, 2, 3, 4]:
        if msg_num not in session.messages:
            continue

        packet = session.messages[msg_num]
        raw_data = get_raw_data(packet)
        if not raw_data:
            continue

        eapol_offset = find_eapol_offset(raw_data)
        if eapol_offset is None:
            continue

        print(f"\nMessage {msg_num}/4:")
        print(f"  Total packet size: {len(raw_data)} bytes")
        print(f"  EAPOL offset: {eapol_offset}")

        # Print first 100 bytes of EAPOL data in hex
        eapol_data = raw_data[eapol_offset:eapol_offset + 100]
        print(f"  First 100 bytes of EAPOL:")
        for i in range(0, len(eapol_data), 16):
            hex_str = ' '.join(f'{b:02x}' for b in eapol_data[i:i+16])
            print(f"    {i:04x}: {hex_str}")

    print("="*70 + "\n")


def print_handshake_hash_info(session, pcap_filename):
    """
    Print the extracted hash information for password cracking.

    Args:
        session: HandshakeSession object
        pcap_filename: Name of the saved PCAP file
    """
    # Verify handshake quality
    is_valid, warnings = verify_handshake_quality(session)

    print(f"\n{Colors.CYAN}{Colors.BOLD}{'═'*70}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}    HANDSHAKE HASH INFORMATION (for password cracking){Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'═'*70}{Colors.RESET}")

    # Show validation status
    if is_valid:
        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ HANDSHAKE VALIDATION: PASSED{Colors.RESET}")
    else:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  HANDSHAKE VALIDATION: WARNINGS DETECTED{Colors.RESET}")
        print(f"{Colors.YELLOW}Warnings:{Colors.RESET}")
        for warning in warnings:
            print(f"{Colors.YELLOW}  • {warning}{Colors.RESET}")

    print(f"\n{Colors.CYAN}AP MAC (BSSID)  :{Colors.RESET} {Colors.BOLD}{Colors.YELLOW}{session.ap_mac}{Colors.RESET}")
    print(f"{Colors.CYAN}Client MAC (STA):{Colors.RESET} {Colors.BOLD}{Colors.YELLOW}{session.client_mac}{Colors.RESET}")

    if session.ssid:
        print(f"{Colors.CYAN}SSID (ESSID)    :{Colors.RESET} {Colors.BOLD}{Colors.GREEN}{session.ssid}{Colors.RESET}")
    else:
        print(f"{Colors.CYAN}SSID (ESSID)    :{Colors.RESET} {Colors.RED}{Colors.BOLD}*** NOT CAPTURED ***{Colors.RESET}")
        print(f"{Colors.RED}                  You will need to specify SSID manually!{Colors.RESET}")

    if session.anonce:
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}ANonce (32 bytes):{Colors.RESET}")
        print(f"  {Colors.CYAN}{session.anonce.hex()}{Colors.RESET}")
    else:
        print(f"\n{Colors.RED}ANonce: Not extracted{Colors.RESET}")

    if session.snonce:
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}SNonce (32 bytes):{Colors.RESET}")
        print(f"  {Colors.CYAN}{session.snonce.hex()}{Colors.RESET}")
    else:
        print(f"\n{Colors.RED}SNonce: Not extracted{Colors.RESET}")

    if session.mic:
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}MIC (16 bytes):{Colors.RESET}")
        print(f"  {Colors.CYAN}{session.mic.hex()}{Colors.RESET}")
    else:
        print(f"\n{Colors.RED}MIC: Not extracted{Colors.RESET}")

    print(f"\n{Colors.YELLOW}{Colors.BOLD}{'─'*70}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}    USAGE INSTRUCTIONS:{Colors.RESET}")
    print(f"{Colors.YELLOW}{Colors.BOLD}{'─'*70}{Colors.RESET}")

    if session.ssid:
        print(f"{Colors.CYAN}1. PCAP file contains beacon with SSID: {Colors.BOLD}{Colors.GREEN}{pcap_filename}{Colors.RESET}")
        print(f"\n{Colors.CYAN}2. To crack with aircrack-ng:{Colors.RESET}")
        print(f"   {Colors.GREEN}aircrack-ng -w wordlist.txt {pcap_filename}{Colors.RESET}")
        print(f"   {Colors.DIM}OR with explicit SSID:{Colors.RESET}")
        print(f"   {Colors.GREEN}aircrack-ng -w wordlist.txt -e '{session.ssid}' {pcap_filename}{Colors.RESET}")
    else:
        print(f"{Colors.CYAN}1. PCAP file saved: {Colors.BOLD}{Colors.YELLOW}{pcap_filename}{Colors.RESET}")
        print(f"\n{Colors.RED}{Colors.BOLD}⚠️  WARNING:{Colors.RESET} {Colors.YELLOW}SSID not captured! You MUST specify it manually:{Colors.RESET}")
        print(f"   {Colors.GREEN}aircrack-ng -w wordlist.txt -e 'NETWORK_NAME' {pcap_filename}{Colors.RESET}")
        print(f"   {Colors.DIM}(Replace 'NETWORK_NAME' with the actual WiFi network name){Colors.RESET}")

    print(f"\n{Colors.CYAN}3. To convert for hashcat (requires hcxtools):{Colors.RESET}")
    print(f"   {Colors.GREEN}hcxpcapngtool -o output.hc22000 {pcap_filename}{Colors.RESET}")
    print(f"   {Colors.GREEN}hashcat -m 22000 output.hc22000 wordlist.txt{Colors.RESET}")

    print(f"\n{Colors.CYAN}4. For hashcat old format (if needed):{Colors.RESET}")
    print(f"   {Colors.GREEN}hcxpcaptool -z output.hccapx {pcap_filename}{Colors.RESET}")
    print(f"   {Colors.GREEN}hashcat -m 2500 output.hccapx wordlist.txt{Colors.RESET}")

    if not session.ssid:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}{'⚠️ '*35}{Colors.RESET}")
        print(f"{Colors.YELLOW}{Colors.BOLD}IMPORTANT: Capture beacon frames to get SSID automatically!{Colors.RESET}")
        print(f"{Colors.YELLOW}The sniffer now captures beacons - wait for the next handshake.{Colors.RESET}")
        print(f"{Colors.YELLOW}{Colors.BOLD}{'⚠️ '*35}{Colors.RESET}")

    # Print troubleshooting tips if validation failed
    if not is_valid:
        print(f"\n{Colors.RED}{Colors.BOLD}{'─'*70}{Colors.RESET}")
        print(f"{Colors.RED}{Colors.BOLD}    TROUBLESHOOTING:{Colors.RESET}")
        print(f"{Colors.RED}{Colors.BOLD}{'─'*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}If aircrack-ng fails to crack the handshake:{Colors.RESET}")
        print(f"{Colors.CYAN}1.{Colors.RESET} Ensure the SSID is correct (case-sensitive)")
        print(f"{Colors.CYAN}2.{Colors.RESET} Verify the password is in your wordlist")
        print(f"{Colors.CYAN}3.{Colors.RESET} Check that all 4 messages were captured")
        print(f"{Colors.CYAN}4.{Colors.RESET} Try capturing a new handshake (wait for a client reconnect)")
        print(f"{Colors.CYAN}5.{Colors.RESET} Verify your wireless card captured packets correctly")
        print(f"\n{Colors.DIM}To view raw EAPOL data for debugging, check the output above.{Colors.RESET}")
        print(f"{Colors.RED}{Colors.BOLD}{'─'*70}{Colors.RESET}")

    print(f"{Colors.CYAN}{Colors.BOLD}{'═'*70}{Colors.RESET}\n")

    # Print raw EAPOL data for advanced debugging
    if not is_valid:
        print_raw_eapol_data(session)


def is_eapol_packet(packet):
    """Check if packet contains EAPOL data."""
    # Must be a Dot11 data frame
    if not packet.haslayer(Dot11):
        return False
    
    dot11 = packet[Dot11]
    # Type 2 = Data frame
    if dot11.type != 2:
        return False
    
    # Skip encrypted packets - EAPOL handshake is always unencrypted
    if packet.haslayer(Dot11CCMP) or packet.haslayer(Dot11TKIP):
        return False
    
    # Check for SNAP layer with EAPOL ethertype
    if packet.haslayer(SNAP):
        snap = packet[SNAP]
        if hasattr(snap, 'code') and snap.code == 0x888e:
            return True
    
    # Check LLC layer
    if packet.haslayer(LLC):
        llc = packet[LLC]
        if hasattr(llc, 'code') and llc.code == 0x888e:
            return True
    
    # Check raw data for EAPOL ethertype
    raw_data = get_raw_data(packet)
    if raw_data and len(raw_data) >= 8:
        # Look for SNAP header with EAPOL: AA AA 03 00 00 00 88 8E
        if raw_data[0:3] == b'\xaa\xaa\x03' and raw_data[6:8] == b'\x88\x8e':
            return True
    
    return False


def get_raw_data(packet):
    """Extract raw data from packet, trying different layers."""
    # For EAPOL, we want the data AFTER the SNAP header
    # SNAP has the ethertype, EAPOL data comes after
    
    # Try SNAP payload (this is where EAPOL data should be)
    if packet.haslayer(SNAP):
        snap = packet[SNAP]
        if snap.payload:
            return bytes(snap.payload)
    
    # Try LLC payload as fallback
    if packet.haslayer(LLC):
        llc = packet[LLC]
        if llc.payload:
            return bytes(llc.payload)
    
    # Try Raw layer
    if packet.haslayer(Raw):
        return bytes(packet[Raw])
    
    # Last resort: get from Dot11 payload
    if packet.haslayer(Dot11):
        dot11 = packet[Dot11]
        if dot11.payload:
            payload = bytes(dot11.payload)
            # Skip past LLC/SNAP if present (8 bytes: AA AA 03 00 00 00 XX XX)
            if len(payload) >= 8 and payload[0:3] == b'\xaa\xaa\x03':
                return payload[8:]  # Return data after LLC/SNAP
            return payload
    
    return None


def find_eapol_offset(raw_data):
    """
    Find the offset where EAPOL data starts.
    For packets with SNAP payload, offset should be 0 (already stripped).
    """
    if raw_data is None or len(raw_data) < 4:
        return None
    
    # If we already have EAPOL data at the start (version should be 1-3)
    # EAPOL format: version(1) | type(1) | length(2) | ...
    if raw_data[0] in [1, 2, 3] and raw_data[1] in [0, 1, 2, 3, 4]:
        return 0
    
    # Otherwise look for 0x888e ethertype and skip past it
    for i in range(0, min(20, len(raw_data) - 2)):
        if raw_data[i:i+2] == b'\x88\x8e':
            return i + 2
    
    return None


def get_message_number(packet):
    """
    Extract the message number (1-4) from an EAPOL handshake packet.

    Returns:
        int: Message number (1, 2, 3, or 4), or None if not a handshake message
    """
    raw_data = get_raw_data(packet)
    if raw_data is None:
        return None

    try:
        eapol_offset = find_eapol_offset(raw_data)
        if eapol_offset is None or len(raw_data) < eapol_offset + 7:
            return None

        eapol_type = raw_data[eapol_offset + 1]
        if eapol_type != 3:  # Must be EAPOL-Key
            return None

        key_info = int.from_bytes(raw_data[eapol_offset + 5:eapol_offset + 7], byteorder='big')

        key_type_pairwise = bool(key_info & 0x0008)
        install = bool(key_info & 0x0040)
        ack = bool(key_info & 0x0080)
        mic = bool(key_info & 0x0100)
        secure = bool(key_info & 0x0200)

        # Determine message number based on flags
        if key_type_pairwise and ack and not mic and not install:
            return 1
        elif key_type_pairwise and mic and not ack and not install and not secure:
            return 2
        elif key_type_pairwise and ack and mic and install and secure:
            return 3
        elif key_type_pairwise and mic and not ack and secure and not install:
            return 4
        else:
            return None  # Not a standard handshake message

    except Exception:
        return None


def get_handshake_step(packet):
    """
    Determine which step of the 4-way handshake an EAPOL packet represents.

    Returns:
        str: Description of the handshake step
    """
    raw_data = get_raw_data(packet)
    if raw_data is None:
        return "Could not extract packet data"
    
    try:
        # Find where EAPOL starts
        eapol_offset = find_eapol_offset(raw_data)
        if eapol_offset is None:
            return "Not an EAPOL packet"
        
        if len(raw_data) < eapol_offset + 4:
            return "Malformed EAPOL packet"
        
        eapol_type = raw_data[eapol_offset + 1]
        
        # EAPOL type 3 = EAPOL-Key (used in 4-way handshake)
        if eapol_type != 3:
            return f"EAPOL Type {eapol_type} (not a key frame)"
        
        # Key Information field starts at offset + 5
        if len(raw_data) < eapol_offset + 7:
            return "Malformed EAPOL-Key packet"
        
        # Key Information is 2 bytes (big endian)
        key_info = int.from_bytes(raw_data[eapol_offset + 5:eapol_offset + 7], byteorder='big')

        # Bit flags in Key Information field:
        # Bit 0-2 (0x0007): Key Descriptor Version
        # Bit 3   (0x0008): Key Type (0=Group, 1=Pairwise)
        # Bit 6   (0x0040): Install flag
        # Bit 7   (0x0080): Key ACK flag
        # Bit 8   (0x0100): Key MIC flag
        # Bit 9   (0x0200): Secure flag
        # Bit 10  (0x0400): Error flag
        # Bit 11  (0x0800): Request flag
        # Bit 12  (0x1000): Encrypted Key Data flag
        
        key_type_pairwise = bool(key_info & 0x0008)
        install = bool(key_info & 0x0040)
        ack = bool(key_info & 0x0080)
        mic = bool(key_info & 0x0100)
        secure = bool(key_info & 0x0200)
        
        # Determine handshake step based on flags
        # Message 1: Pairwise, ACK, no MIC, no Install
        if key_type_pairwise and ack and not mic and not install:
            return "Message 1/4: ANonce from AP (Authenticator → Supplicant)"
        
        # Message 2: Pairwise, MIC, no ACK, no Install, no Secure
        elif key_type_pairwise and mic and not ack and not install and not secure:
            return "Message 2/4: SNonce from Client (Supplicant → Authenticator)"
        
        # Message 3: Pairwise, ACK, MIC, Install, Secure
        elif key_type_pairwise and ack and mic and install and secure:
            return "Message 3/4: GTK from AP (Authenticator → Supplicant)"
        
        # Message 4: Pairwise, MIC, no ACK, Secure, no Install
        elif key_type_pairwise and mic and not ack and secure and not install:
            return "Message 4/4: Confirmation from Client (Supplicant → Authenticator)"
        
        # Group Key Handshake (happens after 4-way)
        elif not key_type_pairwise:
            if ack and mic:
                return "Group Key Message 1/2: GTK Update from AP"
            elif mic and not ack:
                return "Group Key Message 2/2: Confirmation from Client"
            else:
                return f"Group Key Message (Key Info: 0x{key_info:04x})"
        
        else:
            # Provide detailed flag info for unknown combinations
            flags = []
            if key_type_pairwise:
                flags.append("Pairwise")
            else:
                flags.append("Group")
            if ack:
                flags.append("ACK")
            if mic:
                flags.append("MIC")
            if install:
                flags.append("Install")
            if secure:
                flags.append("Secure")
            
            return f"Unknown handshake step (Flags: {', '.join(flags)}, Key Info: 0x{key_info:04x})"
            
    except Exception as e:
        return f"Error parsing EAPOL: {str(e)}"


def handle_eapol_packet(packet):
    """
    Process and print details of an EAPOL packet.

    Args:
        packet: Scapy packet object
    """
    # Check if this is an encrypted packet that looks like EAPOL
    if packet.haslayer(Dot11) and packet[Dot11].type == 2:
        if packet.haslayer(Dot11CCMP) or packet.haslayer(Dot11TKIP):
            # This is encrypted data, skip silently
            return

    if not is_eapol_packet(packet):
        return

    # Extract message number first to determine if this is a handshake message
    message_num = get_message_number(packet)

    # Get BSSID for display
    bssid = "Unknown"
    if packet.haslayer(Dot11):
        dot11 = packet[Dot11]
        bssid = dot11.addr3 if dot11.addr3 else "Unknown"

    # Handshake step identification
    handshake_step = get_handshake_step(packet)

    # Print simple one-liner for EAPOL packet with colors
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.CYAN}[{timestamp}]{Colors.RESET} {Colors.YELLOW}⚡ EAPOL:{Colors.RESET} {Colors.GREEN}{handshake_step}{Colors.RESET} {Colors.DIM}|{Colors.RESET} {Colors.MAGENTA}BSSID:{Colors.RESET} {Colors.BOLD}{bssid}{Colors.RESET}")

    # Save to handshake session if this is a valid handshake message
    if message_num is not None and packet.haslayer(Dot11):
        dot11 = packet[Dot11]
        bssid = dot11.addr3 if dot11.addr3 else None
        src_mac = dot11.addr2 if dot11.addr2 else None
        dst_mac = dot11.addr1 if dot11.addr1 else None

        if bssid and src_mac and dst_mac:
            # Determine AP and Client MACs
            # Messages 1 & 3: AP → Client (src=AP, dst=Client)
            # Messages 2 & 4: Client → AP (src=Client, dst=AP)
            if message_num in [1, 3]:
                ap_mac = src_mac
                client_mac = dst_mac
            else:  # message_num in [2, 4]
                ap_mac = dst_mac
                client_mac = src_mac

            # Get or create handshake session
            session = get_or_create_session(ap_mac, client_mac)

            # Check if we already have this message
            already_had = session.has_message(message_num)

            # Save the message
            session.add_message(message_num, packet)

            if not already_had:
                # Check if handshake is now complete
                if session.is_complete():
                    SUCCESS_W = 63  # inner visual width of the success box
                    INFO_W = 61     # inner visual width of the info table

                    captured_row = f"          {Colors.CYAN}*** COMPLETE HANDSHAKE CAPTURED! ***{Colors.GREEN}"
                    duration = (session.last_updated - session.first_seen).total_seconds()
                    M = Colors.MAGENTA

                    print(f"\n{Colors.GREEN}{Colors.BOLD}")
                    print(f"    ╔{'═'*SUCCESS_W}╗")
                    print(f"    ║{' '*SUCCESS_W}║")
                    print(f"    ║  {Colors.YELLOW}███████╗██╗   ██╗ ██████╗ ██████╗███████╗███████╗███████╗{Colors.GREEN}  ║")
                    print(f"    ║  {Colors.YELLOW}██╔════╝██║   ██║██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝{Colors.GREEN}  ║")
                    print(f"    ║  {Colors.YELLOW}███████╗██║   ██║██║     ██║     █████╗  ███████╗███████╗{Colors.GREEN}  ║")
                    print(f"    ║  {Colors.YELLOW}╚════██║██║   ██║██║     ██║     ██╔══╝  ╚════██║╚════██║{Colors.GREEN}  ║")
                    print(f"    ║  {Colors.YELLOW}███████║╚██████╔╝╚██████╗╚██████╗███████╗███████║███████║{Colors.GREEN}  ║")
                    print(f"    ║  {Colors.YELLOW}╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝{Colors.GREEN}  ║")
                    print(f"    ║{' '*SUCCESS_W}║")
                    print(f"    ║{ansi_ljust(captured_row, SUCCESS_W)}║")
                    print(f"    ║{' '*SUCCESS_W}║")
                    print(f"    ╚{'═'*SUCCESS_W}╝")
                    print(f"{Colors.RESET}")

                    info_rows = [
                        f" {Colors.CYAN}AP MAC      :{Colors.RESET} {Colors.BOLD}{Colors.YELLOW}{session.ap_mac}{Colors.RESET}",
                        f" {Colors.CYAN}Client MAC  :{Colors.RESET} {Colors.BOLD}{Colors.YELLOW}{session.client_mac}{Colors.RESET}",
                        f" {Colors.CYAN}Started at  :{Colors.RESET} {Colors.GREEN}{session.first_seen.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}",
                        f" {Colors.CYAN}Completed at:{Colors.RESET} {Colors.GREEN}{session.last_updated.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}",
                        f" {Colors.CYAN}Duration    :{Colors.RESET} {Colors.YELLOW}{duration:.2f} seconds{Colors.RESET}",
                    ]
                    print(f"{M}    ┌{'─'*INFO_W}┐{Colors.RESET}")
                    for row in info_rows:
                        print(f"{M}    │{Colors.RESET}{ansi_ljust(row, INFO_W)}{M}│{Colors.RESET}")
                    print(f"{M}    └{'─'*INFO_W}┘{Colors.RESET}\n")

                    # Extract cryptographic data from the handshake
                    print(f"{Colors.CYAN}    [*] Extracting handshake data...{Colors.RESET}")
                    if extract_handshake_data(session):
                        print(f"{Colors.GREEN}    [✓] Handshake data extracted successfully{Colors.RESET}")

                        # Verify data quality
                        is_valid, warnings = verify_handshake_quality(session)
                        if warnings:
                            print(f"\n{Colors.YELLOW}    [⚠] Validation warnings:{Colors.RESET}")
                            for warning in warnings:
                                print(f"{Colors.YELLOW}        • {warning}{Colors.RESET}")

                        # Save to PCAP file
                        pcap_file = save_handshake_to_pcap(session)
                        if pcap_file:
                            print(f"\n{Colors.GREEN}{Colors.BOLD}    [✓] Handshake saved to: {Colors.CYAN}{pcap_file}{Colors.RESET}")

                            # Print hash information for cracking
                            print_handshake_hash_info(session, pcap_file)
                        else:
                            print(f"{Colors.RED}    [✗] Failed to save PCAP file{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}    [✗] Failed to extract handshake data{Colors.RESET}")

                    # Print summary of all handshakes after each completion
                    print_handshake_summary()


def print_handshake_summary():
    """Print a summary of all captured handshake sessions."""
    if not handshake_sessions:
        print(f"\n{Colors.YELLOW}No handshake sessions captured.{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}{Colors.BOLD}{'═'*70}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}    HANDSHAKE CAPTURE SUMMARY{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'═'*70}{Colors.RESET}")

    complete_sessions = [s for s in handshake_sessions.values() if s.is_complete()]
    incomplete_sessions = [s for s in handshake_sessions.values() if not s.is_complete()]

    print(f"\n{Colors.CYAN}Total sessions:{Colors.RESET} {Colors.BOLD}{len(handshake_sessions)}{Colors.RESET}")
    print(f"{Colors.GREEN}Complete handshakes:{Colors.RESET} {Colors.BOLD}{Colors.GREEN}{len(complete_sessions)}{Colors.RESET}")
    print(f"{Colors.YELLOW}Incomplete handshakes:{Colors.RESET} {Colors.BOLD}{Colors.YELLOW}{len(incomplete_sessions)}{Colors.RESET}")

    if complete_sessions:
        print(f"\n{Colors.GREEN}{Colors.BOLD}╔═══ COMPLETE HANDSHAKES ═══╗{Colors.RESET}")
        for session in complete_sessions:
            print(f"\n{Colors.CYAN}  AP:{Colors.RESET} {Colors.BOLD}{Colors.YELLOW}{session.ap_mac}{Colors.RESET}")
            print(f"{Colors.CYAN}  Client:{Colors.RESET} {Colors.BOLD}{Colors.YELLOW}{session.client_mac}{Colors.RESET}")
            print(f"{Colors.CYAN}  Messages:{Colors.RESET} {Colors.GREEN}{session.get_progress()}{Colors.RESET}")
            print(f"{Colors.CYAN}  Captured in:{Colors.RESET} {Colors.MAGENTA}{(session.last_updated - session.first_seen).total_seconds():.2f} seconds{Colors.RESET}")

    if incomplete_sessions:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}╔═══ INCOMPLETE HANDSHAKES ═══╗{Colors.RESET}")
        for session in incomplete_sessions:
            print(f"\n{Colors.CYAN}  AP:{Colors.RESET} {Colors.BOLD}{Colors.YELLOW}{session.ap_mac}{Colors.RESET}")
            print(f"{Colors.CYAN}  Client:{Colors.RESET} {Colors.BOLD}{Colors.YELLOW}{session.client_mac}{Colors.RESET}")
            print(f"{Colors.CYAN}  Messages:{Colors.RESET} {Colors.YELLOW}{session.get_progress()}{Colors.RESET}")

    print(f"\n{Colors.CYAN}{Colors.BOLD}{'═'*70}{Colors.RESET}\n")


def handle_packet(packet):
    """
    Unified packet handler for both beacon frames and EAPOL packets.

    Args:
        packet: Scapy packet object
    """
    # Handle beacon frames first (to capture SSIDs)
    if packet.haslayer(Dot11) and packet[Dot11].type == 0:
        handle_beacon_frame(packet)
        return  # Don't print anything for beacons

    # Handle EAPOL packets
    if is_eapol_packet(packet):
        handle_eapol_packet(packet)


def change_channel(interface, channel):
    """
    Change the WiFi channel on the specified interface.

    Args:
        interface: Network interface in monitor mode
        channel: Channel number to set (1-14)

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Try using iw command first (modern method)
        result = subprocess.run(['sudo','iw', 'dev', interface, 'set', 'channel', str(channel)],
                              capture_output=True, text=True)
        if result.returncode == 0:
            return True

        # Fallback to iwconfig (older method)
        result = subprocess.run(['iwconfig', interface, 'channel', str(channel)],
                              capture_output=True, text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"Error changing channel: {e}")
        return False


def channel_hopper(interface):
    """
    Background thread that changes WiFi channels every 5 minutes.
    Cycles through channels 1-11 (common 2.4GHz channels).

    Args:
        interface: Network interface in monitor mode
    """
    global stop_channel_hopping
    channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]  # 2.4GHz channels
    current_channel_index = 0

    print(f"\n{Colors.MAGENTA}{Colors.BOLD}[CHANNEL HOPPER]{Colors.RESET} {Colors.CYAN}Starting - will change channel every 5 minutes{Colors.RESET}")
    print(f"{Colors.MAGENTA}{Colors.BOLD}[CHANNEL HOPPER]{Colors.RESET} {Colors.YELLOW}Cycling through channels: {channels}{Colors.RESET}\n")

    while not stop_channel_hopping:
        channel = channels[current_channel_index]
        timestamp = datetime.now().strftime("%H:%M:%S")

        if change_channel(interface, channel):
            print(f"{Colors.CYAN}[{timestamp}]{Colors.RESET} {Colors.MAGENTA}[CHANNEL HOPPER]{Colors.RESET} {Colors.GREEN}→ Switched to channel {Colors.BOLD}{channel}{Colors.RESET}")
        else:
            print(f"{Colors.CYAN}[{timestamp}]{Colors.RESET} {Colors.MAGENTA}[CHANNEL HOPPER]{Colors.RESET} {Colors.RED}✗ Failed to switch to channel {channel}{Colors.RESET}")

        current_channel_index = (current_channel_index + 1) % len(channels)

        # Wait for 5 minutes (300 seconds) or until stopped
        for _ in range(300):
            if stop_channel_hopping:
                break
            time.sleep(1)

    print(f"\n{Colors.MAGENTA}{Colors.BOLD}[CHANNEL HOPPER]{Colors.RESET} {Colors.RED}Stopped{Colors.RESET}")


def start_monitoring(interface, target_bssid=None):
    """
    Start monitoring for EAPOL packets and beacon frames on the specified interface.

    Args:
        interface: Network interface in monitor mode (e.g., 'wlan0mon')
        target_bssid: Optional - filter for specific AP MAC address
    """
    global stop_channel_hopping

    # Print sick banner
    print_banner()

    print(f"{Colors.GREEN}{Colors.BOLD}[*] Starting WiFi handshake capture on {Colors.CYAN}{interface}{Colors.RESET}")
    if target_bssid:
        print(f"{Colors.YELLOW}[!] Filtering for BSSID: {Colors.BOLD}{target_bssid}{Colors.RESET}")

    BW = 63  # capture mode box inner visual width
    B = f"{Colors.MAGENTA}{Colors.BOLD}"
    cm_rows = [
        f" {Colors.CYAN}CAPTURE MODE:{Colors.RESET}",
        f"  {Colors.GREEN}✓{Colors.RESET} Beacon frames (to extract SSID)",
        f"  {Colors.GREEN}✓{Colors.RESET} EAPOL 4-way handshake packets (unencrypted)",
        f"  {Colors.GREEN}✓{Colors.RESET} Auto channel hopping: {Colors.YELLOW}every 5 minutes{Colors.RESET}",
    ]
    print(f"\n{B}╔{'═'*BW}╗{Colors.RESET}")
    for row in cm_rows:
        print(f"{B}║{Colors.RESET}{ansi_ljust(row, BW)}{B}║{Colors.RESET}")
    print(f"{B}╚{'═'*BW}╝{Colors.RESET}")

    print(f"\n{Colors.YELLOW}{Colors.BOLD}[!] HOW TO TRIGGER A HANDSHAKE:{Colors.RESET}")
    print(f"{Colors.CYAN}    *{Colors.RESET} Wait for a client to connect/reconnect to an AP")

    print(f"\n{Colors.BOLD}{Colors.GREEN}[*] Monitoring...{Colors.RESET}\n")

    # Start channel hopping thread
    stop_channel_hopping = False
    hopper_thread = threading.Thread(target=channel_hopper, args=(interface,), daemon=True)
    hopper_thread.start()

    # Create a filter function
    def packet_filter(pkt):
        if not pkt.haslayer(Dot11):
            return False

        dot11 = pkt[Dot11]

        # Apply BSSID filter if specified
        if target_bssid:
            bssid = dot11.addr3
            if bssid and bssid.lower() != target_bssid.lower():
                return False

        # Accept beacon frames (type 0) or EAPOL packets
        if dot11.type == 0:  # Management frame (includes beacons)
            return True

        return is_eapol_packet(pkt)

    try:
        # Sniff for 802.11 frames (beacons and EAPOL)
        sniff(iface=interface,
              prn=handle_packet,
              lfilter=packet_filter,
              store=0)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}{Colors.BOLD}[!] Capture stopped by user.{Colors.RESET}")
        stop_channel_hopping = True
        print_handshake_summary()
    except Exception as e:
        print(f"\n{Colors.RED}{Colors.BOLD}[✗] Error during capture:{Colors.RESET} {Colors.YELLOW}{e}{Colors.RESET}")
        stop_channel_hopping = True
        print_handshake_summary()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{Colors.RED}{Colors.BOLD}[!] Error: Missing required argument{Colors.RESET}\n")
        print(f"{Colors.YELLOW}Usage:{Colors.RESET} {Colors.GREEN}python3 eapol_handler.py <interface> [target_bssid]{Colors.RESET}\n")
        print(f"{Colors.CYAN}Examples:{Colors.RESET}")
        print(f"  {Colors.GREEN}python3 eapol_handler.py wlan0mon{Colors.RESET}")
        print(f"  {Colors.GREEN}python3 eapol_handler.py wlan0mon AA:BB:CC:DD:EE:FF{Colors.RESET}")
        sys.exit(1)

    interface = sys.argv[1]
    target_bssid = sys.argv[2] if len(sys.argv) > 2 else None

    start_monitoring(interface, target_bssid)
