"""Exploratory pass: run the unmodified Stage 2/3/4 pipeline against every remaining
attack capture (MS AS1-4, DM AS1-3, CompositeAttack) to check for the same kind of
surprise the DoS capture produced (an identity artefact showing up as a side effect).

Not part of the three-scenario paper pipeline -- this is reconnaissance to decide
whether DoS is still the right representative attack example, or whether another
scenario tells a better/cleaner story.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from parse_observed import extract  #noqa: E402
from resolve_classify import load_csv, resolve, classify  #noqa: E402

ROOT = Path(__file__).resolve().parent.parent
ATTACK_DIR = ROOT / "data" / "IEC61850SecurityDataset" / "Attack"
DECLARED_PATH = ROOT / "output" / "declared_assets.csv"

CAPTURES = {
    "ms_as1": ATTACK_DIR / "Message Suppression (MS)" / "AS1.pcapng",
    "ms_as2": ATTACK_DIR / "Message Suppression (MS)" / "AS2.pcapng",
    "ms_as3": ATTACK_DIR / "Message Suppression (MS)" / "AS3.pcapng",
    "ms_as4": ATTACK_DIR / "Message Suppression (MS)" / "AS4.pcapng",
    "dm_as1": ATTACK_DIR / "Data Manipulation (DM)" / "AS1.pcapng",
    "dm_as2": ATTACK_DIR / "Data Manipulation (DM)" / "AS2.pcapng",
    "dm_as3": ATTACK_DIR / "Data Manipulation (DM)" / "AS3.pcapng",
    "composite": ATTACK_DIR / "CompositeAttack.pcapng",
}


def main():
    declared = load_csv(DECLARED_PATH)
    d_names = {d["declared_id"] for d in declared}

    for name, path in CAPTURES.items():
        rows = extract(path)
        #flag anything structurally interesting: >1 name candidate resolving to
        #the same declared id from different MACs, or any MAC with >1 distinct
        #name candidate across the whole capture (same signature as the DoS find)
        multi_name_macs = [r for r in rows if len(set(r["name_candidates"].split(";"))) > 1]

        observed_csv_rows = [
            {
                "observed_id": r["observed_id"],
                "ip": r["ip"] or "",
                "mac": r["mac"],
                "observed_dst_mac": r["observed_dst_mac"],
                "observed_appid": r["observed_appid"],
                "protocols_seen": r["protocols_seen"],
                "name_candidates": r["name_candidates"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "inferred_role": r["inferred_role"],
                "evidence_count": r["evidence_count"],
            }
            for r in rows
        ]
        matches = resolve(declared, observed_csv_rows)
        classified = classify(declared, observed_csv_rows, matches)

        counts = {}
        for c in classified:
            key = (c["delta_class"], c["category"])
            counts[key] = counts.get(key, 0) + 1

        evidence_by_mac = {r["mac"]: int(r["evidence_count"]) for r in rows}
        baseline_note = ""

        print(f"=== {name} ({path.name}) ===")
        print(f"  observed publishers: {len(rows)}")
        print(f"  class/category counts: {counts}")
        if multi_name_macs:
            for r in multi_name_macs:
                print(f"  MULTI-IDENTITY MAC: {r['mac']} claims {r['name_candidates']} (evidence_count={r['evidence_count']})")
        unresolved = [c for c in classified if c["delta_class"] == "Undeclared"]
        for u in unresolved:
            print(f"  UNDECLARED: {u['observed_id']}")
        print()


if __name__ == "__main__":
    main()
