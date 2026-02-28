# GEM → IMS/EMS Vulnerability Translator

### Rule-based, uncertainty-aware building typology mapping for seismic risk

---

## Table of Contents

1. [What This Does](#1-what-this-does)
2. [Files in This Project](#2-files-in-this-project)
3. [Quick Start](#3-quick-start)
4. [GEM Taxonomy String Primer](#4-gem-taxonomy-string-primer)
5. [How the Engine Works](#5-how-the-engine-works)
6. [Output Keys Reference](#6-output-keys-reference)
7. [Vulnerability Class Modifiers](#7-vulnerability-class-modifiers)
8. [Uncertainty and Confidence](#8-uncertainty-and-confidence)
9. [Editing the Engine (Zone A Guide)](#9-editing-the-engine-zone-a-guide)
10. [Processing Exposure Data in Bulk](#10-processing-exposure-data-in-bulk)
11. [Backward Compatibility (v1 → v3)](#11-backward-compatibility-v1--v3)
12. [Mathematical Reference](#12-mathematical-reference)
13. [Governance Rules](#13-governance-rules)
14. [References](#14-references)

---

## 1. What This Does

This project translates a **GEM Building Taxonomy v2.0** string — a structured
description of a building's material, lateral system, height, and design
quality — into the corresponding EMS98/IMS string with information needed for seismic damage and loss assessment:

| Output | Example | Used for |
|---|---|---|
| IMS/EMS building type | `RC1-L`, `M5`, `S-M/H` | Selecting fragility or vulnerability function |
| Vulnerability Class distribution | `{A:0.13, B:0.27, C:0.40, D:0.20}` | Macroseismic intensity methods |
| Most likely VC class | `C` | Point estimate for rapid assessment |
| Confidence score | `0.83` | Weighting results in downstream analysis |

The engine is designed for use in the **SHAKEmaps Toolkit**
pipeline for rapid post-earthquake consequence estimation, but is
self-contained and usable independently.

---

## 2. Files in This Project

```
gem2ems_engine.py        Main engine — single file, no external config needed.
                         Contains all rules, vocabularies, and logic.
                         This is the current version (v3). Use this.

translator_engine.py     Original engine (v1). Requires rules.yaml and
                         ems_vocab.csv. Kept for reference and backward
                         compatibility. Do not use for new work.


ems_vocab.csv            EMS building type vocabulary for v1 engine.
                         27 building types with VC prior distributions
                         (vc_prior_A … vc_prior_F).


```

---

## 3. Quick Start

```python
from gem2ems_engine import gem2ems, to_dataframe

# No arguments needed — all configuration is inside the file
eng = gem2ems()

# --- Single string ---
result = eng.translate("CR/LFINF(MUR+CBH)+CDL+DUL/H:3/IND")

print(result.vc_class)          # "C"   — final VC class
print(result.vc_class_base)     # "C"   — VC before modifiers
print(result.vc_class_int)      # 3     — A=1 through F=6
print(result.confidence)        # 0.830
print(result.summary["best_ems_type"])        # "RC1-L"
print(result.summary["n_modifiers_fired"])    # 1
print(result.summary["cumulative_shift"])     # 0.25
print(result.vc_probs)          # {"A": 0.09, "B": 0.21, "C": 0.44, "D": 0.24, ...}
print(result.vc_probs_base)     # {"A": 0.13, "B": 0.27, "C": 0.40, "D": 0.20, ...}

# --- Batch processing ---
strings = [
    "CR/LFINF(MUR+CBH)+CDL+DUL/H:3/IND",
    "MUR+STRUB/LWAL+DNO/H:2/IND",
    "MUR+CBH/LWAL+DNO/H:4/IND",
    "S/LFBR+CDM+DUM/H:5/IND",
    "W/LWAL+CDL+DUM/H:2/IND",
]
results = eng.translate(strings)
df = to_dataframe(results)
print(df[["gem_str", "best_ems_type", "vc_class_base", "vc_class", "confidence"]])
```

**Dependencies:** Standard library only for the engine core. `pandas` required
only for `to_dataframe()`. Python 3.8+.

---

## 4. GEM Taxonomy String Primer

GEM taxonomy strings use `/` to separate attribute blocks and `+` to
separate tokens within a block. Empty leading/trailing slashes are ignored.

```
CR / LFINF(MUR+CBH) + CDL + DUL / H:3 / IND
│    │                │     │      │     │
│    │                │     │      │     └── Occupancy: IND (industrial)
│    │                │     │      └── Height: H:3 = exactly 3 storeys
│    │                │     └── Ductility: DUL (low structural ductility)
│    │                └── Code level: CDL (low seismic design code)
│    └── System: LFINF = infilled RC frame
│        Infill: MUR+CBH = masonry + concrete hollow block (parenthetical)
└── Material: CR = reinforced concrete
```

### 4.1 The 13 GEM v2.0 Attributes

| # | Attribute | Example tokens |
|---|---|---|
| 1 | Direction | `DX`, `DY`, `D99` |
| 2 | Material | `CR`, `MUR`, `S`, `W`, `MR`, `EU` … |
| 3 | Lateral system (LLRS) | `LFM`, `LFINF`, `LWAL`, `LDUAL`, `LFLS` … |
| 4 | Height | `H:3`, `HBET:7-9`, `HBET:10+`, `HEX:5`, `H:UNK` |
| 5 | Date of construction | `YEX:1985`, `YBET:1970,1980`, `YPRE:1939` |
| 6 | Occupancy | `RES`, `COM4`, `EDU2`, `IND`, `GOV2` … |
| 7 | Building position | `BPD`, `BP1`, `BP2`, `BP3` |
| 8 | Plan shape | `PLFSQ`, `PLFR`, `PLFL`, `PLFH` … |
| 9 | Irregularity | `IRRE+IRVP+SOS`, `IRIR+IRPP+TOR` … |
| 10 | Exterior walls | `EWMA`, `EWC`, `EWE`, `EWG` … |
| 11 | Roof | `RSH1+RMT9`, `RSH3+RWO1+RTD99` … |
| 12 | Floor | `FC1`, `FW+FWCP`, `FE99` … |
| 13 | Foundation | `FOSSL`, `FOSN`, `FOSDN` … |

All token sets from the GEM v2.0 PDF Appendix A are built into the engine.

### 4.2 Ductility tokens — two-token convention

Your exposure data uses a two-token convention instead of the GEM standard
single token. Both conventions are handled simultaneously:

| Tokens in data | ERD label | ERD score | Meaning |
|---|---|---|---|
| `CDL + DUL` | L | 0.10 | Low code, low ductility |
| `CDL + DUM` | L | 0.25 | Low code, moderate ductility |
| `CDM + DUL` | M | 0.40 | Moderate code, low ductility |
| `CDM + DUM` | M | 0.55 | Moderate code, moderate ductility |
| `CDL + DNO` | L | 0.05 | Low code, non-ductile |
| `CDM + DNO` | L | 0.20 | Moderate code, non-ductile |
| `DNO` alone | L | 0.05 | Confirmed non-ductile (GEM standard) |
| `DUC` alone | H | 0.90 | Confirmed ductile (GEM standard) |
| `DBD` alone | H | 1.00 | Base-isolated / energy dissipation |

### 4.3 Height tokens

| Token format | Example | Parsed as |
|---|---|---|
| `H:n` | `H:3` | 3 storeys |
| `H:UNK` | `H:UNK` | Unknown — flagged, height_bin = None |
| `HBET:a-b` | `HBET:7-9` | 9 storeys (upper bound used) |
| `HBET:n+` | `HBET:10+` | 10 storeys (lower bound of open range) |
| `HEX:n` | `HEX:5` | 5 storeys |
| `HAPP:n` | `HAPP:4` | 4 storeys |

Height bins: **L** = 1–3 storeys, **M** = 4–7, **H** = 8+.

### 4.4 Infilled frame notation

A non-standard parenthetical extension is supported for infill material:

```
LFINF(MUR+CBH)+CDL+DUL   →   system = LFINF
                               infill_material = ["MUR", "CBH"]
                               code_level = CDL, ductility_token = DUL
```

The infill material is available to modifier rules independently from the
main material (e.g., the `INFILL_MASONRY_ON_RC` modifier fires on the infill
tokens even when the structural material is `CR`).

### 4.5 Material aliases

Non-standard shorthands found in real data are resolved automatically:

| Found in data | Resolved to | Meaning |
|---|---|---|
| `ST` | `ST99` | Stone, type unknown |
| `CL` | `CL99` | Clay unit, type unknown |
| `UNK` | `MAT99` | Material unknown |

---

## 5. How the Engine Works

### 5.1 Processing pipeline

```
Input GEM string
       │
       ▼
 ┌───────────┐
 │  PARSER   │  Splits blocks by "/", tokens by "+".
 │           │  Handles parenthetical infill, numeric height/year tokens,
 │           │  all 13 GEM attributes, dual ductility token convention.
 └─────┬─────┘
       │  structured feature dict
       ▼
 ┌────────────────────┐
 │  EMS RULE ENGINE   │  Applies EMS_TYPE_RULES in priority order.
 │                    │  First pass: determine material family (RC / MASONRY /
 │                    │  STEEL / TIMBER). Second pass: assign EMS type(s).
 │                    │  Returns one or more candidates with weights.
 └──────────┬─────────┘
            │  EMS candidates + weights
            ▼
 ┌──────────────────────────┐
 │  BASE VC DISTRIBUTION    │  Mixes VC priors from EMS_VOCAB weighted by
 │                          │  EMS candidate probabilities:
 │                          │  p_base(VC|GEM) = Σ p(VC|t) · p(t|GEM)
 └──────────────┬───────────┘
                │  base VC distribution
                ▼
 ┌─────────────────────────────────┐
 │  VC MODIFIER ENGINE             │  Evaluates all VC_MODIFIERS.
 │                                 │  Each matching rule shifts the VC
 │                                 │  distribution smoothly. Shifts sum and
 │                                 │  are clamped. IMS bounds enforced.
 └────────────────┬────────────────┘
                  │  final VC distribution
                  ▼
           TRANSLATION RESULT
```

### 5.2 Exact overrides

Before returning, the engine checks if the exact input string matches an entry
in `EXACT_OVERRIDES`. If it does, all rules and modifiers are bypassed and the
override result is returned directly with confidence ≈ 0.99. Overrides can
optionally force a specific VC class in addition to the EMS type.

### 5.3 EMS type assignment rules

Rules in `EMS_TYPE_RULES` are evaluated in ascending `priority` order. The
engine stops at the first matching rule. Rules have three output forms:

| `then` key | Behavior |
|---|---|
| `"ems_type": "M1"` | Single deterministic type — all probability on M1 |
| `"ems_template": "RC1-{erd}"` | Template filled from parsed ERD level (L/M/H) |
| `"fallback": "BRICK_MASONRY"` | Probabilistic distribution from FALLBACK_PRIORS |

Priority bands used in the engine:

| Range | Purpose |
|---|---|
| 10–12 | Family assignment from material token |
| 15–17 | Earth and adobe subtypes |
| 20–29 | Masonry unit subtypes (rubble, dressed stone, brick, block) |
| 28–29 | Precast RC |
| 30–33 | RC system rules (frame, wall, dual, flat slab) |
| 50–62 | Steel and timber subtypes |
| 70–85 | Family-level fallbacks (missing system or detail) |
| 999 | Global failsafe — returns M4 if nothing else matched |

### 5.4 VC distribution shifting

When a modifier rule fires, it shifts the distribution by a specified amount.
Positive shift = more vulnerable (toward A). Negative shift = less vulnerable
(toward F).

**Mechanism:** A shift of 1.0 moves all mass one bin toward the target
direction. A shift of 0.5 interpolates halfway. The shift is smooth and
continuous — no abrupt jumps.

**Bounds:** The IMS exceptional range (`vc_range_min` / `vc_range_max` in
`EMS_VOCAB`) acts as a hard wall. Mass cannot leave this range regardless of
how large the shift is.

**Cap:** The sum of all shifts is clamped to ±`MAX_CUMULATIVE_SHIFT` (default
2.0) before being applied.

---

## 6. Output Keys Reference

The `translate()` method returns a `TranslationResult` dataclass.

### Top-level

| Key | Type | Description |
|---|---|---|
| `gem_str` | str | Input string |
| `vc_class` | str | Final modal VC class — `"A"` to `"F"` |
| `vc_class_int` | int | Final VC as integer — A=1, B=2 … F=6 |
| `vc_class_base` | str | Modal VC before any modifiers |
| `vc_class_base_int` | int | Base VC as integer |
| `vc_probs` | dict | Final VC distribution `{"A":…, "B":…, …}` |
| `vc_probs_base` | dict | Base VC distribution before modifiers |
| `confidence` | float | Final confidence score [0, 1] |
| `warnings` | list[str] | Parser and rule warnings |
| `ems_candidates` | list[dict] | Ranked EMS types with weights, confidence, rule_id |
| `vc_modifiers_applied` | list[dict] | Fired modifier rules with id, shift, penalty |

### `parsed` sub-dict — all 13 GEM attributes

| Key | Description |
|---|---|
| `material` | L1 material token |
| `material_L2` | L2 material tokens (unit type, reinforcement, concrete tech) |
| `material_L3` | L3 tokens (mortar type, stone type) |
| `material_all` | All material tokens combined |
| `system` | LLRS L1 token |
| `system_L2` | LLRS L2 tokens |
| `infill_material` | Infill tokens from `LFINF(…)` notation |
| `erd` | ERD level: `"L"` / `"M"` / `"H"` |
| `erd_score` | Continuous ERD score [0, 1] |
| `code_level` | `CDL` / `CDM` if present |
| `ductility_token` | `DUL` / `DUM` / `DNO` / `DUC` / `DBD` if present |
| `height_stories` | Integer storey count or `None` |
| `height_bin` | `"L"` / `"M"` / `"H"` or `None` |
| `year_value` | Numeric year or `None` |
| `year_token_type` | `YEX` / `YBET` / `YPRE` / `YAPP` |
| `occupancy` | Occupancy L1 code |
| `occupancy_detail` | Occupancy L2 code (e.g. `COM4`, `EDU2`) |
| `position` | `BP1` / `BP2` / `BP3` / `BPD` |
| `plan_shape` | `PLF*` token |
| `irregularity_L1` | `IRRE` / `IRIR` / `IR99` |
| `irregularity_plan_types` | List: `TOR`, `REC`, `IRHO` |
| `irregularity_vert_types` | List: `SOS`, `SHC`, `CRW`, `POP`, `SET`, `CHV` |
| `exterior_walls` | List of `EW*` tokens |
| `roof_shape` | `RSH*` token |
| `roof_covering` | `RMT*` token |
| `roof_system_material` | Roof system material token |
| `roof_connections` | List of `RWC*` / `RTD*` tokens |
| `floor_material` | Floor material token |
| `floor_connection` | `FWCP` / `FWCN` / `FWC99` |
| `foundation` | `FOS*` token |
| `family` | Derived: `RC` / `MASONRY` / `STEEL` / `TIMBER` |

### `summary` sub-dict

| Key | Description |
|---|---|
| `best_ems_type` | Most probable EMS type |
| `best_ems_weight` | Probability of best EMS type |
| `best_vc_mode` | Final modal VC class (same as `vc_class`) |
| `best_vc_mode_base` | Modal VC before modifiers |
| `best_vc_mode_final` | Alias for `best_vc_mode` |
| `vc_credible_range_80` | Smallest VC range covering 80% probability, final — e.g. `"B-D"` |
| `vc_credible_range_80_base` | Same for base distribution |
| `exact_override` | `True` if an exact override was applied |
| `n_modifiers_fired` | Number of modifier rules that fired |
| `cumulative_shift` | Total VC shift applied after capping |

### `uncertainty` sub-dict

| Key | Description |
|---|---|
| `missing_features` | List of GEM attributes absent from the string |
| `ems_entropy` | Shannon entropy of EMS type distribution |
| `vc_entropy` | Shannon entropy of final VC distribution |
| `vc_entropy_base` | Shannon entropy of base VC distribution |
| `top1_margin` | Weight gap between the top two EMS candidates |
| `modifier_confidence_penalty` | Product of all fired modifier penalties |
| `flags` | Diagnostic flags (see table below) |

### Flags

| Flag | Meaning |
|---|---|
| `ONE_TO_MANY_MAPPING` | Probabilistic (fallback) EMS type assignment was used |
| `ERD_DEFAULTED_TO_L` | No ductility token found; ERD defaulted to L |
| `SYSTEM_MISSING` | No LLRS system token was parsed |
| `HEIGHT_MISSING` | Height unknown or unparseable |
| `VC_MODIFIER_APPLIED` | At least one modifier rule fired |
| `EXACT_OVERRIDE` | Result came from an exact override entry |
| `EMS_NOT_IN_VOCAB` | A rule produced an EMS type not in EMS_VOCAB (replaced with M4) |

---

## 7. Vulnerability Class Modifiers

Modifiers adjust the base VC distribution using building information encoded
in the GEM string. They are defined as a list of rule dicts in `VC_MODIFIERS`
(Zone A, Section A7) and are fully editable.

### 7.1 Modifier structure

```python
{
    "id":    "IRREG_SOFT_STOREY",
    "doc":   "Soft storey (SOS) — concentrates inter-storey drift. "
             "Primary failure mode in virtually every major earthquake.",
    "if": {
        "irregularity_vert_type_in": ["SOS"],
    },
    "shift": +1.00,               # positive = toward A (more vulnerable)
    "confidence_penalty": 0.88,   # multiplied into final confidence
    "max_contribution": 1.00,     # optional: cap this rule's contribution
},
```

### 7.2 Modifier groups and shift magnitudes

| Group | Key rules | Shift range | Source |
|---|---|---|---|
| Structural irregularity | Soft storey, short column, cripple wall, torsion, pounding | +0.25 to +1.00 | IMS-25; post-earthquake surveys |
| Plan shape | Complex plans, openings; regular rectangle bonus | ±0.25 | Geometric torsional eccentricity |
| Age / code era | Pre-1920 (+1.25) to post-2000 (−0.25); post-2010+ductile (−0.75) | ±0.25 to ±1.25 | Seismic code development history |
| Ductility / ERD | DNO (+0.5), DUC (−0.75), DBD (−1.25) | −1.25 to +0.50 | IMS-25 Section 3.7 |
| Roof system | Earthen on masonry (+1.5); light metal/shingle (−0.25) | −0.25 to +1.50 | IMS-25; Turkey, Iran, Haiti observations |
| Floor diaphragm | Wood floor on masonry (+0.75), disconnected (+0.5) | −0.25 to +0.75 | L'Aquila 2009, Christchurch 2011 |
| Masonry material quality | No mortar (+0.75); RC bond beams (−0.75) | −0.75 to +0.75 | Masonry engineering; Turkish surveys |
| Building position | Corner (+0.5), end-of-row (+0.25), detached (−0.25) | −0.25 to +0.50 | Pounding risk |
| Occupancy | Critical facilities, schools, informal housing (+0.25 to +0.5) | 0 to +0.50 | Building importance factors |
| Foundation | Deep without lateral (+0.5), shallow without lateral (+0.25) | −0.25 to +0.50 | Soft-soil seismic performance |
| Exterior walls / infill | Masonry infill on RC (+0.25), earthen infill (+0.5) | −0.25 to +0.50 | Mediterranean infill-RC interaction |
| Precast RC | RC5/RC6 without ductility info (+0.5) | +0.50 | Historical precast connection quality |

### 7.3 Condition keys available in modifier `if` dicts

Conditions within a single rule are ANDed. For OR logic within one attribute,
use a list (e.g. `"system_any": ["LFM", "LFINF"]`). For OR across different
attributes, write two separate rules.

| Condition key | Matches when |
|---|---|
| `family_is` / `family_in` | `parsed.family` equals / is in list |
| `material_any` | `material`, `material_L2`, or `material_all` contains any token in list |
| `material_L2_any` | `material_L2` contains any token in list |
| `material_L3_any` | `material_L3` contains any (mortar type, stone type) |
| `system_is` / `system_any` | `system` equals / is in list |
| `infill_any` | `infill_material` contains any token in list |
| `erd_is` | `erd` equals `"L"` / `"M"` / `"H"` |
| `erd_score_below` / `erd_score_above` | `erd_score` < / >= value |
| `ductility_token_is` / `ductility_token_in` | `ductility_token` equals / is in list |
| `code_level_is` | `code_level` equals value |
| `height_bin_is` / `height_bin_in` | `height_bin` equals / is in list |
| `height_stories_above` | `height_stories` > value |
| `year_known` | `year_value` is not `None` — use `True` or `False` |
| `year_before` | `year_value < value` |
| `year_after_eq` | `year_value >= value` |
| `occupancy_L1_is` | `occupancy` equals value |
| `occupancy_detail_in` | `occupancy_detail` is in list |
| `position_in` | `position` is in list |
| `plan_shape_in` | `plan_shape` is in list |
| `irregularity_L1_is` | `irregularity_L1` equals value |
| `irregularity_plan_type_in` | `irregularity_plan_types` contains any; `[]` means "no plan type present" |
| `irregularity_vert_type_in` | `irregularity_vert_types` contains any; `[]` means "no vert type present" |
| `roof_covering_in` | `roof_covering` is in list |
| `roof_system_in` | `roof_system_material` equals or starts with any value in list |
| `floor_material_in` | `floor_material` equals or starts with any value in list |
| `floor_conn_is` | `floor_connection` equals value |
| `roof_conn_in` | `roof_connections` contains any token in list |
| `foundation_in` | `foundation` is in list |
| `exterior_wall_any` | `exterior_walls` contains any token in list |
| `ems_type_in` | Final EMS type is in list (useful for precast-specific rules) |

---

## 8. Uncertainty and Confidence

### 8.1 What the confidence score means

| Range | Typical situation |
|---|---|
| 0.90 – 0.95 | Full string: material + system + height + ductility, deterministic EMS type, no modifiers |
| 0.75 – 0.90 | Good string, one or two modifiers fired, deterministic EMS type |
| 0.50 – 0.75 | Height or ductility missing, or probabilistic EMS assignment |
| 0.20 – 0.50 | Multiple missing attributes, or ambiguous material (C99, MATO) |
| < 0.20 | Effectively unknown building (UNK material, failsafe applied) |

### 8.2 Entropy

**EMS entropy** measures ambiguity in the building type assignment. Zero means
a single deterministic type was assigned. A high value means several types
have comparable probability and the result is uncertain.

**VC entropy (base vs. final)** tells you what the modifiers did. If
`vc_entropy < vc_entropy_base`, the modifiers sharpened the prediction —
strong evidence in one direction. If `vc_entropy > vc_entropy_base`, the
modifiers spread the distribution, indicating conflicting evidence. Comparing
these two values is useful for diagnosing modifier behavior across a dataset.

### 8.3 Modifier confidence penalties

Each modifier carries a `confidence_penalty` in [0, 1] that is multiplied into
the final confidence when the rule fires. Rules that fire on directly observed
tokens (e.g. `RTDP` — roof tie-down explicitly coded) use penalty = 1.0.
Rules that fire on inferred proxies (e.g. infill type inferred from exterior
wall token) use 0.88–0.92. The product of all penalties is reported as
`modifier_confidence_penalty` in the uncertainty sub-dict.

### 8.4 80% credible VC range

The `vc_credible_range_80` is the shortest contiguous VC interval such that
the summed probability covers at least 80% of the distribution. A narrow range
such as `"C-D"` indicates a confident prediction. A wide range such as `"A-D"`
indicates high uncertainty.

### 8.5 Monte Carlo use

```python
import random

def sample_one(result):
    """Draw one EMS type and one VC class from the result distributions."""
    # Sample EMS type
    r = random.random()
    cum = 0.0
    ems = result.ems_candidates[-1]["ems_type"]
    for c in result.ems_candidates:
        cum += c["weight"]
        if r <= cum:
            ems = c["ems_type"]
            break
    # Sample VC from final distribution
    r2 = random.random()
    cum2 = 0.0
    vc = "D"
    for cls in ["A", "B", "C", "D", "E", "F"]:
        cum2 += result.vc_probs.get(cls, 0.0)
        if r2 <= cum2:
            vc = cls
            break
    return ems, vc

# Run 1000 Monte Carlo samples
samples = [sample_one(result) for _ in range(1000)]
```

---

## 9. Editing the Engine (Zone A Guide)

`gem2ems_engine.py` is divided into three zones. **Only Zone A should ever
need editing.** Zone B is the engine logic and Zone C is utilities.

```
ZONE A — Configuration   ← edit here
ZONE B — Engine          ← do not edit
ZONE C — Utilities       ← do not edit
```

### 9.1 Add a new EMS type assignment rule

Add a new dict to `EMS_TYPE_RULES` in Zone A. Choose a `priority` that fits
where you want it evaluated:

```python
{
    "id":       "MAS_LIMESTONE",
    "priority": 22,
    "if": {
        "family":          "MASONRY",
        "material_L2_any": ["SPLI"],      # limestone
    },
    "then": {
        "fallback": "STONE_DRESSED",      # limestone → M3/M4 distribution
    },
    "confidence_penalty": 0.85,
    "doc": "Limestone (SPLI) treated as dressed stone. M3/M4 distribution.",
},
```

### 9.2 Add a new VC modifier rule

Add a new dict to `VC_MODIFIERS` in Zone A:

```python
{
    "id":    "MASONRY_VAULT_FLOOR",
    "doc":   "Vaulted masonry floors produce lateral thrust similar to vault roofs.",
    "if": {
        "floor_material_in": ["FM1", "FM2"],   # masonry vault floor
        "family_in":         ["MASONRY"],
    },
    "shift": +0.50,
    "confidence_penalty": 0.90,
},
```

Shift magnitudes to use as a guide:
- ±0.25 — mild effect, one secondary feature
- ±0.50 — moderate effect, important but not dominant
- ±0.75 — significant effect, well-documented failure mechanism
- ±1.00 — strong effect, primary observed collapse cause
- ±1.25 or more — extreme effect, use sparingly and document the evidence

### 9.3 Add an exact override

For a GEM string you have independently verified, add an entry to
`EXACT_OVERRIDES`:

```python
{
    "gem":        "CR+CIP/LDUAL+DUC/H:10/COM4",
    "ems_type":   "RC3-H",
    "confidence": 0.99,
    "doc":        "Verified cast-in-place dual system, confirmed ductile, "
                  "10-storey hospital. Source: field survey 2025-06-01.",
},
```

Optionally, add `"vc_class": "E"` to also force a specific VC class,
bypassing all modifiers.

### 9.4 Adjust VC prior distributions

Edit the `"vc_prior"` dict for the relevant type in `EMS_VOCAB`. Values must
sum to 1.0. Also check `vc_range_min` and `vc_range_max` — these are the
IMS exceptional range bounds and control how far modifiers can push the
distribution.

### 9.5 Add a material alias

If a new non-standard token appears in your data, add it to
`MATERIAL_ALIASES` in Zone A:

```python
MATERIAL_ALIASES = {
    "ST":  "ST99",
    "CL":  "CL99",
    "UNK": "MAT99",
    "BK":  "CL99",    # new: "brick" shorthand found in dataset X
}
```

### 9.6 Adjust the ductility mapping

To support a new token combination, add a row to `DUCTILITY_MAP`:

```python
("CDH", "DUH"): {"erd": "H", "erd_score": 0.90, "label": "high-code, high-ductility"},
```

---

## 10. Processing Exposure Data in Bulk

### 10.1 From a CSV file

```python
import csv, pandas as pd
from gem2ems_engine import gem2ems, to_dataframe

eng = gem2ems()

exposure = pd.read_csv("Exposure_Turkey.csv")
results = eng.translate(exposure["TAXONOMY"].tolist())
df = to_dataframe(results)

# Merge back
exposure["ems_type"]      = df["best_ems_type"].values
exposure["vc_class"]      = df["vc_class"].values
exposure["vc_class_base"] = df["vc_class_base"].values
exposure["confidence"]    = df["confidence"].values
exposure["vc_range_80"]   = df["vc_range_80"].values
```

### 10.2 DataFrame columns from `to_dataframe()`

**Original columns (v1, unchanged):**
`gem_str`, `best_ems_type`, `best_ems_weight`, `best_vc_mode`, `vc_range_80`,
`confidence`, `ems_entropy`, `vc_entropy`, `missing_features`

**New columns (v3):**
`vc_class`, `vc_class_int`, `vc_class_base`, `vc_class_base_int`,
`vc_probs_A` through `vc_probs_F`,
`vc_probs_base_A` through `vc_probs_base_F`,
`vc_range_80_base`, `vc_entropy_base`,
`n_modifiers_fired`, `cumulative_shift`, `mod_conf_penalty`,
`flags`, `material`, `system`, `erd`, `height_bin`, `occupancy`, `family`

### 10.3 Inspecting modifier behavior on a specific string

```python
r = eng.translate("MUR+CBH/LWAL+DNO/H:4/IND")

print(f"Base VC: {r.vc_class_base}  →  Final VC: {r.vc_class}")
print(f"Cumulative shift: {r.summary['cumulative_shift']:+.2f}")
print()
for m in r.vc_modifiers_applied:
    print(f"  [{m['id']}]  shift={m['shift']:+.2f}  "
          f"penalty={m['confidence_penalty']:.2f}")
    print(f"  {m['doc'][:70]}")
```

### 10.4 Checking for warnings and problems

```python
results = eng.translate(taxonomies)
problems = [(r.gem_str, r.warnings) for r in results if r.warnings]
for gem, ws in problems:
    print(gem, ws)

# Check flags
flagged = [(r.gem_str, r.uncertainty["flags"]) for r in results
           if "SYSTEM_MISSING" in r.uncertainty["flags"]]
```

### 10.5 Running the built-in smoke test

```bash
python gem2ems_engine.py
```

This runs a set of 16 test strings and prints a summary table. All 324 unique
taxonomy strings from the Turkey industrial exposure dataset are processed with
zero warnings.

---

## 11. Backward Compatibility (v1 → v3)

`gem2ems_engine.py` is a drop-in replacement for `translator_engine.py`.
All v1 output key names are preserved. The class alias `TranslatorEngine`
is also preserved.

| v1 pattern | Works in v3? | Notes |
|---|---|---|
| `TranslatorEngine()` | ✅ | Alias for `gem2ems` |
| `result.vc_probs` | ✅ | Now = **post-modifier** distribution |
| `result.summary["best_vc_mode"]` | ✅ | Unchanged |
| `result.summary["best_ems_type"]` | ✅ | Unchanged |
| `result.summary["vc_credible_range_80"]` | ✅ | Unchanged |
| `result.summary["exact_override"]` | ✅ | Unchanged |
| `result.uncertainty["flags"]` | ✅ | Unchanged; new flags may appear |
| `result.confidence` | ✅ | Unchanged key; value includes modifier penalty |
| `result.warnings` | ✅ | Unchanged |
| `result.parsed["material"]` | ✅ | Unchanged |
| `result.parsed["erd"]` | ✅ | Unchanged |
| `result.parsed["irregularity"]` | ✅ | Alias for `irregularity_L1` |
| `result.parsed["year_token"]` | ✅ | Unchanged format |
| `to_dataframe(results)` | ✅ | All original columns present |

**One behavioral change to be aware of:** `result.vc_probs` now returns the
post-modifier distribution. If you previously used `vc_probs` for downstream
analysis and want the unmodified prior, use `result.vc_probs_base` instead.

**v1 initialization with file paths is not needed:** `gem2ems_engine.py` has
no external files. The old pattern `TranslatorEngine(base_dir="…")` can be
replaced with the no-argument `gem2ems()`.

---

## 12. Mathematical Reference

### EMS type assignment

```
p(t | GEM)    where t ∈ all EMS types in EMS_VOCAB
```

Deterministic rule: p(t) = 1, all others = 0.

Fallback rule with weights w_i:
```
p(t_i | GEM) = w_i / Σ w_i
```

### Base VC distribution

```
p_base(VC | GEM) = Σ_t  p(VC | t) · p(t | GEM)
```

where p(VC | t) comes from `vc_prior` in `EMS_VOCAB`.

### VC shift mechanics

For total shift s:
- Integer part `floor(|s|)`: probability mass relocated one bin at a time.
- Fractional part `{|s|}`: mass interpolated between current and shifted position.

After shifting:
1. Zero out all mass outside `[vc_range_min, vc_range_max]` (IMS hard bounds).
2. Renormalize.

### Confidence model

```
H_norm = H_ems / log(N_candidates)

conf_mapping = Σ  p(t_i) · confidence_i

mod_penalty = Π  confidence_penalty_j   (product over fired modifiers)

confidence_final = conf_mapping × (1 − α · H_norm) × mod_penalty
```

Default α = 0.25, editable as `ENTROPY_PENALTY_ALPHA` in Zone A.

### 80% credible range

Smallest contiguous interval [lo, hi] such that:
```
Σ_{k = lo}^{hi}  p(VC = k)  ≥  0.80
```

### Shannon entropy

```
H = − Σ  p_k · log(p_k)    (natural logarithm)
```

Used for both EMS type distribution (`ems_entropy`) and VC distribution
(`vc_entropy`, `vc_entropy_base`).

---

## 13. Governance Rules

These rules keep the engine trustworthy and auditable over time.

1. **Document every rule.** Every entry in `EMS_TYPE_RULES`, `VC_MODIFIERS`,
   and `EXACT_OVERRIDES` must have a non-empty `"doc"` field. Write what the
   rule detects, why, and what evidence supports it.

2. **Never remove the FAILSAFE rule** (priority 999 in `EMS_TYPE_RULES`).
   It ensures no input crashes silently and every string gets a result.

3. **Exact overrides are a last resort.** Use them only for strings that have
   been independently verified by field survey, structural drawings, or
   expert assessment. Record the source and date in `"doc"`.

4. **`vc_prior` values must sum to 1.0** for each EMS type. The engine
   normalizes them but the source values should be kept clean.

5. **Large modifier shifts require evidence.** Shifts above ±1.0 should be
   supported by IMS documentation, peer-reviewed literature, or post-earthquake
   survey data. Document the source in `"doc"`.

6. **Do not edit Zone B** unless you are extending the parsing or engine
   architecture. Zone B changes require code review.

7. **Do not remove existing modifiers** without team agreement. Removing a
   rule changes historical results and breaks reproducibility.

8. **Validate after every Zone A change.** Run the smoke test and verify that
   all Turkey dataset strings still process with zero warnings:

   ```bash
   python gem2ems_engine.py
   ```

---

## 14. References

- Brzev S., Scawthorn C., Charleson A.W., Allen L., Greene M., Jaiswal K.,
  Silva V. (2013). *GEM Building Taxonomy Version 2.0*. GEM Technical Report
  2013-02 V1.0.0, 188 pp., GEM Foundation, Pavia, Italy.
  doi: [10.13117/GEM.EXP-MOD.TR2013.02](https://doi.org/10.13117/GEM.EXP-MOD.TR2013.02)

- Wald D.J., Goded T., Hortacsu A., Loos S.C. (2024). *Developing and
  implementing an International Macroseismic Scale (IMS) for earthquake
  engineering, earthquake science, and rapid damage assessment*. U.S.
  Geological Survey Open-File Report 2023–1098, 55 p.
  doi: [10.3133/ofr20231098](https://doi.org/10.3133/ofr20231098)

- Grünthal G. (ed.) (1998). *European Macroseismic Scale 1998 (EMS-98)*.
  Cahiers du Centre Européen de Géodynamique et de Séismologie, Vol. 15,
  Luxembourg.

- FEMA (2015). *Rapid Visual Screening of Buildings for Potential Seismic
  Hazards: A Handbook* (FEMA P-154, Third Edition). Federal Emergency
  Management Agency, Washington, D.C.

---

*Part of the SHAKEmaps Toolkit code*
*Engine: `gem2ems_engine.py` — single file, no external config.*