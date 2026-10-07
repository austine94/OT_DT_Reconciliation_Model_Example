"""Generate the Section IV worked-example table directly from the classifier output,
so a late data change (new scenario, re-run pipeline) costs minutes, not a rewrite.

Reads output/classified_deltas_{normal,perturbed,dos}.csv, writes a markdown table
to Paper_Notes/table1_worked_example.md and prints it to stdout.
"""

import csv
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "output"
TABLE_PATH = ROOT / "Paper_Notes" / "table1_worked_example.md"

SCENARIOS = ["normal", "perturbed_silent", "perturbed_undeclared", "perturbed_identity", "dos"]
SCENARIO_LABELS = {
    "normal": "Normal (clean baseline)",
    "perturbed_silent": "Perturbed -- silent (synthetic, known ground truth)",
    "perturbed_undeclared": "Perturbed -- undeclared (synthetic, known ground truth)",
    "perturbed_identity": "Perturbed -- identity (synthetic, known ground truth)",
    "dos": "DoS attack (real capture)",
}

#(delta_class, category) -> column label, in display order.
#Display-layer renaming only (paper terminology): the classifier's raw
#delta_class/category values are unchanged (see resolve_classify.py) --
#"Conflicted" and dropping "Stale" are labels applied here, not a schema
#change. "Stale" was never an emitted class; "Conflicted" is the paper name
#for the (Misdeclared, security_relevant) identity-conflict case.
COLUMNS = [
    (("Matched", None), "Matched"),
    (("Misdeclared", "data_quality"), "Misdeclared (data-quality)"),
    (("Misdeclared", "security_relevant"), "Conflicted (security-relevant)"),
    (("Silent", "data_quality_or_security"), "Silent"),
    (("Undeclared", "security_relevant"), "Undeclared"),
]


def load_counts(scenario: str) -> dict:
    path = OUT_DIR / f"classified_deltas_{scenario}.csv"
    with path.open() as f:
        rows = list(csv.DictReader(f))
    counts = defaultdict(int)
    for r in rows:
        cat = r["category"] if r["category"] else None
        counts[(r["delta_class"], cat)] += 1
    return counts, len(rows)


def resolution_note(scenario: str) -> str:
    path = OUT_DIR / f"classified_deltas_{scenario}.csv"
    with path.open() as f:
        rows = list(csv.DictReader(f))
    tiers = sorted({r["tier"] for r in rows if r["tier"]})
    confidences = sorted({r["confidence"] for r in rows if r["confidence"]})
    return f"tiers: {', '.join(tiers) or 'none'}; confidence: {', '.join(confidences) or 'none'}"


def main():
    lines = []
    lines.append("# Table 1 — Delta counts by class and category across scenarios")
    lines.append("")
    lines.append(
        "Generated from `output/classified_deltas_{normal,perturbed_silent,perturbed_undeclared,"
        "perturbed_identity,dos}.csv`. `D` = 18 declared IEDs in every scenario; `O` = 18 observed "
        "publishers (normal, dos) / 17 (perturbed-silent — one dropped) / 19 (perturbed-undeclared, "
        "perturbed-identity — one added each)."
    )
    lines.append("")

    header = ["Scenario"] + [label for _, label in COLUMNS] + ["Resolution tiers used"]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join(["---"] * len(header)) + "|")

    for scenario in SCENARIOS:
        counts, total = load_counts(scenario)
        row = [SCENARIO_LABELS[scenario]]
        for key, _ in COLUMNS:
            row.append(str(counts.get(key, 0)))
        row.append(resolution_note(scenario))
        lines.append("| " + " | ".join(row) + " |")

    lines.append("")
    lines.append(
        "Note: `Perturbed -- silent`, `Perturbed -- undeclared`, and `Perturbed -- identity` "
        "are three independent, synthetic, ground-truth-known modifications of the same "
        "clean baseline (see `src/perturb_observed.py`), each isolating exactly one "
        "engineered change and the one residual class it produces -- one asset dropped "
        "(Silent), one unrecognised publisher added (Undeclared), one spoofed-identity "
        "publisher added on top of an untouched genuine device (Conflicted). Among the two "
        "real, unmodified captures (*Normal* and *DoS*), "
        "`Conflicted` fires only in DoS — and, per the exploratory pass over the "
        "remaining 7 attack captures (MS AS1-4, DM AS1-3, CompositeAttack), only in DoS "
        "among all 9 real capture scenarios analysed in total. Every other class stays "
        "flat between *Normal* and *DoS*, isolating `Conflicted` as the one class "
        "sensitive to this dataset's DoS implementation — and only because that "
        "implementation happens to reuse another IED's declared identity, not because of "
        "any volume or timing signal the method reads. The fuzzy-name resolution tier "
        "never fired in any scenario; all resolved matches used exact-name matching, a "
        "consequence of GOOSE's cleartext `gocbRef` field rather than a property of the "
        "resolution method in general."
    )

    table_md = "\n".join(lines)
    TABLE_PATH.write_text(table_md + "\n")
    print(table_md)
    print(f"\nWritten to {TABLE_PATH}")


if __name__ == "__main__":
    main()
