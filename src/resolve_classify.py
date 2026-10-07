"""Stage 3 + 4: deterministic identity resolution and delta classification.

Resolution tiers, in priority order (see README/paper_plan.md):
  1. exact address (IP)      -- not usable: D's IP is uniform across all IEDs,
                                 and GOOSE frames carry no IP layer at all.
  2. MAC / OUI                -- not usable: D never declares each IED's own
                                 source MAC (only the shared GSE destination
                                 MAC), so there is nothing on the D side to
                                 compare O's source MACs against.
  3. exact name match         -- D.declared_id against O.name_candidates.
                                 This is the tier that actually does the work
                                 for this dataset, because GOOSE leaks the IED
                                 name in cleartext (gocbRef).
  4. fuzzy name match         -- fallback for anything tier 3 misses.

The same code runs unmodified against every scenario (normal / perturbed / DoS).
No volume- or timing-based anomaly logic is added deliberately: this is an
asset-reconciliation method, not a detector, and the DoS run is meant to show
that boundary rather than paper over it. Concretely, in the DoS capture 5,000
of LIED10's 11,800 flood frames self-identify as LIED10 (pure volume, no
signal here at all) and 5,000 carry LIED12's identity (caught by the ordinary
name-resolution tier below, not by any volume check). Do not read that catch
as "detects the DoS" -- it's an identity artefact of that specific attack
script, structurally identical to an ordinary misconfiguration (ambiguous
one-declared-to-many-observed matches classify the same way regardless of
whether the cause was spoofing or a copy-pasted duplicate identity). The
taxonomy below classifies structural inconsistency between D and O, not cause.
"""

import csv
import difflib
import sys
from pathlib import Path
from collections import defaultdict

OUT_DIR = Path(__file__).resolve().parent.parent / "output"

FUZZY_THRESHOLD = 0.8


def load_csv(path: Path) -> list[dict]:
    with path.open() as f:
        return list(csv.DictReader(f))


def resolve(declared: list[dict], observed: list[dict]):
    """Return list of match records: {declared_id, observed_id, tier, confidence}."""
    d_by_name = {d["declared_id"]: d for d in declared}
    matches = []
    matched_declared_ids = set()

    #tier 3: exact name match (an observed row may carry >1 name candidate,
    #and >1 observed rows may exact-match the same declared name -- both are
    #kept, since a one-to-many match is itself a finding, not an error).
    unresolved_observed = []
    for o in observed:
        candidates = [c for c in o["name_candidates"].split(";") if c]
        exact_hits = [c for c in candidates if c in d_by_name]
        if exact_hits:
            for c in exact_hits:
                matches.append(
                    {"declared_id": c, "observed_id": o["observed_id"], "tier": "name_exact", "confidence": "high"}
                )
                matched_declared_ids.add(c)
        else:
            unresolved_observed.append(o)

    #tier 4: fuzzy name match, only for observed rows tier 3 couldn't place
    for o in unresolved_observed:
        candidates = [c for c in o["name_candidates"].split(";") if c] or [o["observed_id"]]
        best = None
        for c in candidates:
            close = difflib.get_close_matches(c, d_by_name.keys(), n=1, cutoff=FUZZY_THRESHOLD)
            if close:
                best = close[0]
                break
        if best:
            matches.append(
                {"declared_id": best, "observed_id": o["observed_id"], "tier": "name_fuzzy", "confidence": "low"}
            )
            matched_declared_ids.add(best)
        else:
            matches.append(
                {"declared_id": None, "observed_id": o["observed_id"], "tier": "unresolved", "confidence": "none"}
            )

    return matches


def classify(declared: list[dict], observed: list[dict], matches: list[dict]) -> list[dict]:
    d_by_name = {d["declared_id"]: d for d in declared}
    o_by_id = {o["observed_id"]: o for o in observed}

    matches_by_declared = defaultdict(list)
    matches_by_observed = defaultdict(list)
    for m in matches:
        if m["declared_id"]:
            matches_by_declared[m["declared_id"]].append(m)
        matches_by_observed[m["observed_id"]].append(m)

    rows = []

    for name, d in d_by_name.items():
        hits = matches_by_declared.get(name, [])
        if not hits:
            rows.append(
                {
                    "delta_class": "Silent",
                    "category": "data_quality_or_security",
                    "declared_id": name,
                    "observed_id": None,
                    "tier": None,
                    "confidence": None,
                    "note": "declared but never observed (commissioned-but-inactive vs decommissioned "
                    "is not distinguishable from D/O comparison alone)",
                }
            )
        elif len(hits) == 1:
            o = o_by_id[hits[0]["observed_id"]]
            mismatches = []
            if d["appid"] and o["observed_appid"] and d["appid"] != o["observed_appid"]:
                mismatches.append(f"appid declared={d['appid']} observed={o['observed_appid']}")
            if mismatches:
                rows.append(
                    {
                        "delta_class": "Misdeclared",
                        "category": "data_quality",
                        "declared_id": name,
                        "observed_id": o["observed_id"],
                        "tier": hits[0]["tier"],
                        "confidence": hits[0]["confidence"],
                        "note": "; ".join(mismatches),
                    }
                )
            else:
                rows.append(
                    {
                        "delta_class": "Matched",
                        "category": None,
                        "declared_id": name,
                        "observed_id": o["observed_id"],
                        "tier": hits[0]["tier"],
                        "confidence": hits[0]["confidence"],
                        "note": None,
                    }
                )
        else:
            rows.append(
                {
                    "delta_class": "Misdeclared",
                    "category": "security_relevant",
                    "declared_id": name,
                    "observed_id": ";".join(h["observed_id"] for h in hits),
                    "tier": "name_exact",
                    "confidence": "high_but_ambiguous",
                    "note": f"{len(hits)} distinct sources claim this identity -- structurally indistinguishable "
                    "between spoofing and misconfiguration from D/O comparison alone",
                }
            )

    for observed_id, o in o_by_id.items():
        hits = [m for m in matches_by_observed.get(observed_id, []) if m["declared_id"]]
        if not hits:
            rows.append(
                {
                    "delta_class": "Undeclared",
                    "category": "security_relevant",
                    "declared_id": None,
                    "observed_id": observed_id,
                    "tier": "unresolved",
                    "confidence": "none",
                    "note": "observed publisher with no matching declared identity",
                }
            )

    return rows


def run_scenario(name: str, observed_path: Path, declared_path: Path):
    declared = load_csv(declared_path)
    observed = load_csv(observed_path)
    matches = resolve(declared, observed)
    rows = classify(declared, observed, matches)

    out_path = OUT_DIR / f"classified_deltas_{name}.csv"
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    counts = defaultdict(int)
    for r in rows:
        counts[r["delta_class"]] += 1

    print(f"[{name}] wrote {len(rows)} rows to {out_path}")
    print(f"  {dict(counts)}")
    return counts


def main():
    declared_path = OUT_DIR / "declared_assets.csv"
    scenarios = {
        "normal": OUT_DIR / "observed_assets_normal.csv",
        "perturbed_silent": OUT_DIR / "observed_assets_perturbed_silent.csv",
        "perturbed_undeclared": OUT_DIR / "observed_assets_perturbed_undeclared.csv",
        "perturbed_identity": OUT_DIR / "observed_assets_perturbed_identity.csv",
        "dos": OUT_DIR / "observed_assets_dos.csv",
    }

    summary = {}
    for name, path in scenarios.items():
        summary[name] = run_scenario(name, path, declared_path)

    classes = sorted({c for counts in summary.values() for c in counts})
    summary_path = OUT_DIR / "delta_summary.csv"
    with summary_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["scenario", *classes])
        for name, counts in summary.items():
            writer.writerow([name, *[counts.get(c, 0) for c in classes]])

    print(f"\nSummary written to {summary_path}")


if __name__ == "__main__":
    main()
