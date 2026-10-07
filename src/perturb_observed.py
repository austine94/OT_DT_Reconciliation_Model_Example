"""Build three synthetic, ground-truth-known perturbations of the clean observed set O.

None is derived from real packet bytes -- all are declared, documented
modifications of the clean Normal-scenario extraction, used to demonstrate the
delta taxonomy on cases the real captures don't naturally contain (see the
Stage 2 finding: none of this dataset's attack scenarios introduce a new
identity, so Undeclared/Silent/Conflicted examples have to be engineered by
hand).

Originally built as one combined scenario, then split into two (2026-09-30),
then into three (2026-09-30, same pass) once it was clear the "presence"
scenario was still bundling two changes for no better reason than the first
split hadn't gone far enough: dropping LIED22 and adding a rogue publisher
don't interact with each other any more than either interacts with the
identity-conflict change. Each of the three residual classes engineered here
now gets its own scenario, built from exactly one change to the clean
baseline:

Scenario A -- "silent": DROP LIED22 entirely -> simulates a declared IED that
    goes quiet (Silent; commissioned-but-inactive and actually-decommissioned
    are observationally identical from D/O comparison alone).

Scenario B -- "undeclared": ADD a rogue publisher (new MAC, no matching
    declared name) -> genuine shadow device (Undeclared).

Scenario C -- "identity": ADD a spoofed-identity publisher (new MAC, but
    claims the name "LIED10", which is still genuinely present and unmodified
    in this scenario's observed set) -> creates a one-declared-to-many-observed
    match: a security-relevant identity conflict (Conflicted), distinct from
    the routine APPID mismatch every device already shows (Misdeclared). Note:
    this signature is indistinguishable, by design, from an ordinary
    misconfiguration (e.g. a copy-pasted duplicate identity) -- see the same
    caveat in resolve_classify.py. A real instance of this exact pattern also
    turned up in the DoS attack capture (Stage 4).
"""

import csv
from pathlib import Path

IN_PATH = Path(__file__).resolve().parent.parent / "output" / "observed_assets_normal.csv"
OUT_DIR = Path(__file__).resolve().parent.parent / "output"
OUT_PATH_SILENT = OUT_DIR / "observed_assets_perturbed_silent.csv"
OUT_PATH_UNDECLARED = OUT_DIR / "observed_assets_perturbed_undeclared.csv"
OUT_PATH_IDENTITY = OUT_DIR / "observed_assets_perturbed_identity.csv"

DROP_NAME = "LIED22"

ROGUE_ROW = {
    "observed_id": "de:ad:be:ef:00:99",
    "ip": "",
    "mac": "de:ad:be:ef:00:99",
    "observed_dst_mac": "01:0c:cd:01:00:01",
    "observed_appid": "1000",
    "protocols_seen": "GOOSE",
    "name_candidates": "",  #no recognisable declared name -> genuine shadow device
    "first_seen": "1557387700.0",
    "last_seen": "1557388300.0",
    "inferred_role": "unknown",
    "evidence_count": "42",
}

SPOOFED_ROW = {
    "observed_id": "aa:bb:cc:00:11:22",
    "ip": "",
    "mac": "aa:bb:cc:00:11:22",
    "observed_dst_mac": "01:0c:cd:01:00:01",
    "observed_appid": "1000",
    "protocols_seen": "GOOSE",
    "name_candidates": "LIED10",  #claims an identity that already exists elsewhere
    "first_seen": "1557387700.0",
    "last_seen": "1557388300.0",
    "inferred_role": "control",
    "evidence_count": "17",
}


def write_rows(rows, out_path):
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main():
    with IN_PATH.open() as f:
        clean_rows = list(csv.DictReader(f))

    silent_rows = [r for r in clean_rows if DROP_NAME not in r["name_candidates"].split(";")]
    write_rows(silent_rows, OUT_PATH_SILENT)
    print(f"Wrote {len(silent_rows)} rows to {OUT_PATH_SILENT}")
    print(f"  dropped: {DROP_NAME}")

    undeclared_rows = list(clean_rows)  #nothing removed -- this scenario only adds the rogue publisher
    undeclared_rows.append(ROGUE_ROW)
    write_rows(undeclared_rows, OUT_PATH_UNDECLARED)
    print(f"Wrote {len(undeclared_rows)} rows to {OUT_PATH_UNDECLARED}")
    print(f"  added: rogue publisher {ROGUE_ROW['mac']}")

    identity_rows = list(clean_rows)  #LIED22 stays in -- this scenario only adds the spoofer
    identity_rows.append(SPOOFED_ROW)
    write_rows(identity_rows, OUT_PATH_IDENTITY)
    print(f"Wrote {len(identity_rows)} rows to {OUT_PATH_IDENTITY}")
    print(f"  added: spoofed-identity publisher {SPOOFED_ROW['mac']} claiming LIED10")


if __name__ == "__main__":
    main()
