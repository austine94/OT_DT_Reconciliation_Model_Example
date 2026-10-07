"""Stage 1: parse the IEC 61850 .iid config files into the flat declared-set table D.

Each .iid file describes one IED instance. There is no consolidated SCD in this
dataset, so we union 18 single-IED files instead of reading one substation-wide file.
"""

import csv
from pathlib import Path
from xml.etree import ElementTree as ET

SCL_NS = "http://www.iec.ch/61850/2003/SCL"
NS = {"scl": SCL_NS}

SCL_DIR = Path(__file__).resolve().parent.parent / "data" / "IEC61850SecurityDataset" / "SCL Files"
OUT_PATH = Path(__file__).resolve().parent.parent / "output" / "declared_assets.csv"

#IED name prefix -> role, per the one-line diagram legend (L=Line, T=Transformer, B=Bus, UF=Under frequency)
ROLE_PREFIXES = [
    ("UFIED", "under_frequency"),
    ("BIED", "bus"),
    ("TIED", "transformer"),
    ("LIED", "line"),
]


def infer_role(ied_name: str) -> str:
    for prefix, role in ROLE_PREFIXES:
        if ied_name.startswith(prefix):
            return role
    return "unknown"


def parse_iid(path: Path) -> dict:
    tree = ET.parse(path)
    root = tree.getroot()

    ied_el = root.find("scl:IED", NS)
    name = ied_el.get("name")

    connected_ap = root.find(
        f"scl:Communication/scl:SubNetwork/scl:ConnectedAP[@iedName='{name}']", NS
    )

    ip = connected_ap.find("scl:Address/scl:P[@type='IP']", NS)
    ip = ip.text if ip is not None else None

    gse_address = connected_ap.find("scl:GSE/scl:Address", NS)
    mac = gse_address.find("scl:P[@type='MAC-Address']", NS) if gse_address is not None else None
    appid = gse_address.find("scl:P[@type='APPID']", NS) if gse_address is not None else None

    return {
        "declared_id": name,
        "name": name,
        "address": ip,
        "mac": mac.text if mac is not None else None,
        "appid": appid.text if appid is not None else None,
        "vendor": None,   #not present in this dataset's .iid files
        "model": None,    #not present in this dataset's .iid files
        "firmware": None, #not present in this dataset's .iid files
        "role": infer_role(name),
        "source_file": path.name,
        "source_xpath": f"IED[@name='{name}']",
    }


def main():
    rows = [parse_iid(p) for p in sorted(SCL_DIR.glob("*.iid"))]

    OUT_PATH.parent.mkdir(exist_ok=True)
    with OUT_PATH.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} declared assets to {OUT_PATH}")


if __name__ == "__main__":
    main()
