"""
Automated judge for the PFCP Session Creation Resource Exhaustion challenge.

Listens on the N4 interface (PFCP, UDP/8805) and detects flooding-style
Denial of Service attacks based on unauthorized PFCP session establishment
requests. When the request rate exceeds a threshold within a one-second
window, the judge extracts the attacker's CTFd API token embedded in the
packet payload and submits a solve on their behalf via the CTFd API.
"""

from scapy.all import *
from scapy.contrib.pfcp import *
import requests
import time

api_url = "http://127.0.0.1:8081/api/v1/challenges/attempt"
challenge_id = 8
threshold = 50
count = 0
token_extracted = False
seconds = time.time()


def extract_token(pfcp_payload):
    pfcp_payload_str = pfcp_payload.decode('utf-8', errors='ignore')
    if "Token " in pfcp_payload_str:
        token = pfcp_payload_str.split("Token ")[1].strip()
        return token
    return None


def pfcp_packet_callback(packet):
    global count, token_extracted, seconds
    count += 1
    now = time.time()

    if now - seconds >= 1:
        token_extracted = False
        count = 0
        seconds = now
    elif count >= threshold and not token_extracted:
        if PFCP in packet and packet[PFCP].payload:
            pfcp_payload = bytes(packet[PFCP].payload)
            token = extract_token(pfcp_payload)
            if pfcp_payload:
                token = extract_token(pfcp_payload)
            if token:
                print(f"Token extracted: {token}")
                token_extracted = True
                submission_data = {
                    "challenge_id": challenge_id,
                    "submission": "CTF{You_got_it!}"
                }
                headers = {
                    'Content-Type': 'application/json',
                    'Authorization': f"Token {token}"
                }
                print(packet.show())
                response = requests.post(api_url, headers=headers, json=submission_data)


sniff(filter="udp port 8805", prn=pfcp_packet_callback, iface='lo')
