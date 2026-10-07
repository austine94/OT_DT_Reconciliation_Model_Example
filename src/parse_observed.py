"""Stage 2: extract the observed-set table O from a GOOSE pcap capture.

Scapy has no built-in GOOSE dissector, so GOOSE frames are decoded by hand:
Ethernet(+802.1Q) -> GOOSE header (APPID, Length, Reserved1, Reserved2) -> BER-TLV APDU.

Scope: GOOSE traffic only (ethertype 0x88b8). Other traffic seen in these captures
(DHCP broadcasts, IPv6 mDNS/MLD) is background noise from the capture environment,
not OT devices, and is excluded rather than counted as "undeclared" assets.
"""

import csv
import re
import sys
from pathlib import Path
from collections import defaultdict

from scapy.all import PcapReader, Ether, Dot1Q

GOOSE_ETHERTYPE = 0x88B8

#GOOSE APDU top-level BER tags we care about (IEC 61850-8-1)
TAG_GOCBREF = 0x80
TAG_GOID = 0x83

#strip a trailing logical-device instance (e.g. "CTRL", "PROT") to recover the IED name
LD_INST_SUFFIX = re.compile(r"^([A-Za-z0-9]+?)(CTRL|PROT|MEAS)$")


def ber_length(data: bytes, offset: int) -> tuple[int, int]:
    """Return (length, bytes_consumed_for_length_field) starting at offset."""
    first = data[offset]
    if first & 0x80 == 0:
        return first, 1
    num_bytes = first & 0x7F
    length = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], "big")
    return length, 1 + num_bytes


def parse_goose_apdu(apdu: bytes) -> dict:
    """Walk the top-level TLVs of a GOOSE PDU (tag 0x61 content) and return {tag: value_bytes}."""
    fields = {}
    pos = 0
    while pos < len(apdu):
        tag = apdu[pos]
        length, len_size = ber_length(apdu, pos + 1)
        value_start = pos + 1 + len_size
        value = apdu[value_start : value_start + length]
        fields[tag] = value
        pos = value_start + length
    return fields


def parse_goose_frame(raw: bytes):
    """Given raw bytes from the GOOSE ethertype onward, return (appid, dst_mac_irrelevant, gocbref, goid)."""
    appid = int.from_bytes(raw[0:2], "big")
    pdu_length = int.from_bytes(raw[2:4], "big")
    #header is APPID(2) + Length(2) + Reserved1(2) + Reserved2(2) = 8 bytes
    apdu_start = 8
    apdu = raw[apdu_start:pdu_length]  #pdu_length counts from APPID field
    if not apdu or apdu[0] != 0x61:
        return appid, None, None
    length, len_size = ber_length(apdu, 1)
    body = apdu[1 + len_size : 1 + len_size + length]
    fields = parse_goose_apdu(body)
    gocbref = fields.get(TAG_GOCBREF, b"").decode(errors="replace") or None
    goid = fields.get(TAG_GOID, b"").decode(errors="replace") or None
    return appid, gocbref, goid


def name_candidate(gocbref: str | None) -> str | None:
    if not gocbref:
        return None
    prefix = gocbref.split("/")[0]  #e.g. "LIED40CTRL"
    m = LD_INST_SUFFIX.match(prefix)
    return m.group(1) if m else prefix


def extract(pcap_path: Path) -> list[dict]:
    stations = defaultdict(
        lambda: {
            "mac": None,
            "dst_macs": set(),
            "appids": set(),
            "gocbrefs": set(),
            "name_candidates": set(),
            "first_seen": None,
            "last_seen": None,
            "evidence_count": 0,
        }
    )

    with PcapReader(str(pcap_path)) as pr:
        for pkt in pr:
            if Ether not in pkt:
                continue
            eth = pkt[Ether]
            if Dot1Q in pkt:
                ethertype = pkt[Dot1Q].type
                payload = bytes(pkt[Dot1Q].payload)
            else:
                ethertype = eth.type
                payload = bytes(eth.payload)
            if ethertype != GOOSE_ETHERTYPE:
                continue

            appid, gocbref, goid = parse_goose_frame(payload)
            src_mac = eth.src
            rec = stations[src_mac]
            rec["mac"] = src_mac
            rec["dst_macs"].add(eth.dst)
            rec["appids"].add(appid)
            if gocbref:
                rec["gocbrefs"].add(gocbref)
                rec["name_candidates"].add(name_candidate(gocbref))
            ts = float(pkt.time)
            rec["first_seen"] = ts if rec["first_seen"] is None else min(rec["first_seen"], ts)
            rec["last_seen"] = ts if rec["last_seen"] is None else max(rec["last_seen"], ts)
            rec["evidence_count"] += 1

    rows = []
    for src_mac, rec in sorted(stations.items()):
        names = rec["name_candidates"]
        role = set()
        for g in rec["gocbrefs"]:
            if "CTRL" in g.split("/")[0]:
                role.add("control")
            if "PROT" in g.split("/")[0]:
                role.add("protection")
            if "MEAS" in g.split("/")[0]:
                role.add("measurement")
        rows.append(
            {
                "observed_id": src_mac,
                "ip": None,
                "mac": src_mac,
                "observed_dst_mac": ";".join(sorted(rec["dst_macs"])),
                "observed_appid": ";".join(str(a) for a in sorted(rec["appids"])),
                "protocols_seen": "GOOSE",
                "name_candidates": ";".join(sorted(n for n in names if n)),
                "first_seen": rec["first_seen"],
                "last_seen": rec["last_seen"],
                "inferred_role": ";".join(sorted(role)) or "unknown",
                "evidence_count": rec["evidence_count"],
            }
        )
    return rows


def main():
    pcap_path = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parent.parent
        / "data" / "IEC61850SecurityDataset" / "Normal" / "No_Variable_Loading" / "Normal.pcapng"
    )
    out_path = Path(__file__).resolve().parent.parent / "output" / "observed_assets.csv"

    rows = extract(pcap_path)

    out_path.parent.mkdir(exist_ok=True)
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} observed assets (from {pcap_path.name}) to {out_path}")


if __name__ == "__main__":
    main()
