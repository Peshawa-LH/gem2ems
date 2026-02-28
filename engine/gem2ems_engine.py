"""
gem2ems_engine.py
=================
GEM v2.0 Building Taxonomy → IMS/EMS Vulnerability Translator

Translates a GEM taxonomy string into:
  • IMS/EMS building type (e.g. RC1-L, M5, S-M/H)
  • Vulnerability Class (VC) distribution over {A, B, C, D, E, F}
  • VC class prediction — base (from prior only) and final (after modifiers)
  • Full uncertainty quantification

Single-file design — no external config files required.
Everything editable by the team lives in ZONE A below.

──────────────────────────────────────────────────────────────────────────────
FILE STRUCTURE
──────────────────────────────────────────────────────────────────────────────
  ZONE A  — CONFIGURATION  ← team edits here
              A1  EMS Vocabulary (building types + VC priors)
              A2  Ductility / Code Level Mapping
              A3  Material Aliases
              A4  EMS Type Assignment Rules
              A5  Fallback Priors (uncertain mappings)
              A6  Exact Override Rules
              A7  VC Modifier Rules
              A8  Global Tuning Constants

  ZONE B  — ENGINE         ← do not edit
              GemParser
              gem2ems  (main translation class)

  ZONE C  — UTILITIES
              to_dataframe()

──────────────────────────────────────────────────────────────────────────────
OUTPUT KEYS  (backward-compatible; new keys are additive)
──────────────────────────────────────────────────────────────────────────────
  gem_str                     input taxonomy string
  parsed                      all 13 parsed GEM attributes
  ems_candidates              list of EMS type candidates with weights
  vc_probs                    final VC distribution after modifiers
  vc_probs_base               VC distribution BEFORE modifiers
  summary
    best_ems_type             most probable EMS type
    best_ems_weight           probability of best EMS type
    best_vc_mode              final VC class letter (post-modifier)  ← vc_class
    best_vc_mode_base         VC class letter before modifiers
    vc_credible_range_80      80% credible range (post-modifier)
    vc_credible_range_80_base 80% credible range (pre-modifier)
    exact_override            bool
    n_modifiers_fired         int
    cumulative_shift          float — total shift applied (capped)
  uncertainty
    missing_features          list of missing GEM attributes
    ems_entropy               Shannon entropy of EMS type distribution
    vc_entropy                Shannon entropy of final VC distribution
    vc_entropy_base           Shannon entropy of base VC distribution
    top1_margin               weight gap between top two EMS candidates
    modifier_confidence_penalty  product of all fired modifier penalties
    flags                     list of diagnostic flags
  vc_class                    final VC class letter  ("A"–"F")
  vc_class_int                final VC class as integer (A=1 … F=6)
  vc_class_base               VC class before modifiers
  vc_class_base_int           VC class before modifiers as integer
  confidence                  final confidence score [0, 1]
  warnings                    list of parser / rule warnings
  vc_modifiers_applied        list of fired modifier dicts

Usage
-----
    from gem2ems_engine import gem2ems, to_dataframe

    eng = gem2ems()
    result = eng.translate("CR/LFINF(MUR+CBH)+CDL+DUL/H:3/IND")
    print(result.vc_class, result.vc_class_base)

    results = eng.translate(["CR/LFINF(MUR+CBH)+CDL+DUL/H:3/IND",
                              "MUR+STRUB/LWAL+DNO/H:2/IND"])
    df = to_dataframe(results)
"""

from __future__ import annotations
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

# ═══════════════════════════════════════════════════════════════════════════════
#  ZONE A — CONFIGURATION
#  ─────────────────────────────────────────────────────────────────────────────
#  This is the ONLY section the team should edit.
#  Each sub-section is clearly labelled.  Add rules as new list/dict entries.
#  Do NOT modify anything in ZONE B or ZONE C.
# ═══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# A1 — EMS VOCABULARY
# ─────────────────────────────────────────────────────────────────────────────
# Each entry is one IMS/EMS building type.
#
# Keys per entry:
#   family          : "RC" | "MASONRY" | "STEEL" | "TIMBER"
#   label           : human-readable name (for documentation)
#   vc_prior        : base VC distribution from ems_vocab.csv  (must sum to 1)
#   vc_most_likely  : IMS stated most-likely class
#   vc_range_min    : lowest class in IMS exceptional range  (hard shift bound)
#   vc_range_max    : highest class in IMS exceptional range (hard shift bound)
#   doc             : notes
#
# vc_prior values come from ems_vocab.csv vc_prior_A … vc_prior_F columns.
# vc_range_min / vc_range_max come from vuln_class_min / vuln_class_max in CSV.
# ─────────────────────────────────────────────────────────────────────────────
EMS_VOCAB: Dict[str, Dict[str, Any]] = {

    # ── MASONRY ──────────────────────────────────────────────────────────────
    "M1": {
        "family": "MASONRY",
        "label": "Rubble stone / fieldstone masonry",
        "vc_prior": {"A": 1.000, "B": 0.000, "C": 0.000, "D": 0.000, "E": 0.000, "F": 0.000},
        "vc_most_likely": "A", "vc_range_min": "A", "vc_range_max": "A",
        "doc": "Uncut fieldstone, no or mud mortar. Most vulnerable masonry type.",
    },
    "M2": {
        "family": "MASONRY",
        "label": "Adobe / earth brick masonry",
        "vc_prior": {"A": 0.667, "B": 0.333, "C": 0.000, "D": 0.000, "E": 0.000, "F": 0.000},
        "vc_most_likely": "A", "vc_range_min": "A", "vc_range_max": "B",
        "doc": "Adobe, rammed earth, cob. IMS: most likely A, can reach B.",
    },
    "M3": {
        "family": "MASONRY",
        "label": "Simple stone masonry",
        "vc_prior": {"A": 0.333, "B": 0.667, "C": 0.000, "D": 0.000, "E": 0.000, "F": 0.000},
        "vc_most_likely": "B", "vc_range_min": "A", "vc_range_max": "B",
        "doc": "Dressed stone, some corner bonding. Most likely B, can reach A.",
    },
    "M4": {
        "family": "MASONRY",
        "label": "Massive stone masonry",
        "vc_prior": {"A": 0.000, "B": 0.250, "C": 0.500, "D": 0.250, "E": 0.000, "F": 0.000},
        "vc_most_likely": "C", "vc_range_min": "B", "vc_range_max": "D",
        "doc": "Large cut blocks — castles, civic buildings. IMS: B–D, most likely C.",
    },
    "M5": {
        "family": "MASONRY",
        "label": "Manufactured stone units with timber floors",
        "vc_prior": {"A": 0.250, "B": 0.500, "C": 0.250, "D": 0.000, "E": 0.000, "F": 0.000},
        "vc_most_likely": "B", "vc_range_min": "A", "vc_range_max": "C",
        "doc": "Fired-clay brick / concrete block, timber floors. Most likely B.",
    },
    "M6": {
        "family": "MASONRY",
        "label": "Manufactured stone units with RC floors",
        "vc_prior": {"A": 0.000, "B": 0.250, "C": 0.500, "D": 0.250, "E": 0.000, "F": 0.000},
        "vc_most_likely": "C", "vc_range_min": "B", "vc_range_max": "D",
        "doc": "Brick/block masonry with RC floors. RC floors improve diaphragm.",
    },
    "M7": {
        "family": "MASONRY",
        "label": "Reinforced or confined masonry with RC floors",
        "vc_prior": {"A": 0.000, "B": 0.000, "C": 0.250, "D": 0.500, "E": 0.250, "F": 0.000},
        "vc_most_likely": "D", "vc_range_min": "C", "vc_range_max": "E",
        "doc": "Steel-reinforced or confined masonry. IMS: C–E, most likely D.",
    },

    # ── RC — CAST-IN-SITU ────────────────────────────────────────────────────
    "RC1-L": {
        "family": "RC",
        "label": "RC moment/braced frame, low ERD",
        "vc_prior": {"A": 0.133, "B": 0.267, "C": 0.400, "D": 0.200, "E": 0.000, "F": 0.000},
        "vc_most_likely": "C", "vc_range_min": "A", "vc_range_max": "D",
        "doc": "RC frame without seismic design. Most likely C.",
    },
    "RC1-M": {
        "family": "RC",
        "label": "RC moment/braced frame, moderate ERD",
        "vc_prior": {"A": 0.000, "B": 0.133, "C": 0.267, "D": 0.400, "E": 0.200, "F": 0.000},
        "vc_most_likely": "D", "vc_range_min": "B", "vc_range_max": "E",
        "doc": "RC frame with moderate seismic design. Most likely D.",
    },
    "RC1-H": {
        "family": "RC",
        "label": "RC moment/braced frame, high ERD",
        "vc_prior": {"A": 0.000, "B": 0.000, "C": 0.133, "D": 0.267, "E": 0.400, "F": 0.200},
        "vc_most_likely": "E", "vc_range_min": "C", "vc_range_max": "F",
        "doc": "RC frame with high seismic design. Most likely E.",
    },
    "RC2-L": {
        "family": "RC",
        "label": "RC shear wall, low ERD",
        "vc_prior": {"A": 0.000, "B": 0.250, "C": 0.500, "D": 0.250, "E": 0.000, "F": 0.000},
        "vc_most_likely": "C", "vc_range_min": "B", "vc_range_max": "D",
        "doc": "RC wall without seismic design. More inherent stiffness than frame.",
    },
    "RC2-M": {
        "family": "RC",
        "label": "RC shear wall, moderate ERD",
        "vc_prior": {"A": 0.000, "B": 0.000, "C": 0.250, "D": 0.500, "E": 0.250, "F": 0.000},
        "vc_most_likely": "D", "vc_range_min": "C", "vc_range_max": "E",
        "doc": "RC wall with moderate seismic design.",
    },
    "RC2-H": {
        "family": "RC",
        "label": "RC shear wall, high ERD",
        "vc_prior": {"A": 0.000, "B": 0.000, "C": 0.000, "D": 0.250, "E": 0.500, "F": 0.250},
        "vc_most_likely": "E", "vc_range_min": "D", "vc_range_max": "F",
        "doc": "RC wall with high seismic design.",
    },
    "RC3-L": {
        "family": "RC",
        "label": "RC dual frame-wall system, low ERD",
        "vc_prior": {"A": 0.000, "B": 0.250, "C": 0.500, "D": 0.250, "E": 0.000, "F": 0.000},
        "vc_most_likely": "C", "vc_range_min": "B", "vc_range_max": "D",
        "doc": "Dual system without seismic design.",
    },
    "RC3-M": {
        "family": "RC",
        "label": "RC dual frame-wall system, moderate ERD",
        "vc_prior": {"A": 0.000, "B": 0.000, "C": 0.250, "D": 0.500, "E": 0.250, "F": 0.000},
        "vc_most_likely": "D", "vc_range_min": "C", "vc_range_max": "E",
        "doc": "Dual system with moderate seismic design.",
    },
    "RC3-H": {
        "family": "RC",
        "label": "RC dual frame-wall system, high ERD",
        "vc_prior": {"A": 0.000, "B": 0.000, "C": 0.000, "D": 0.250, "E": 0.500, "F": 0.250},
        "vc_most_likely": "E", "vc_range_min": "D", "vc_range_max": "F",
        "doc": "Dual system with high seismic design.",
    },
    "RC4": {
        "family": "RC",
        "label": "RC flat slab / waffle slab",
        "vc_prior": {"A": 0.200, "B": 0.400, "C": 0.267, "D": 0.133, "E": 0.000, "F": 0.000},
        "vc_most_likely": "B", "vc_range_min": "A", "vc_range_max": "D",
        "doc": "Flat slab — no beams, punch-through risk. Most likely B.",
    },

    # ── RC — PRECAST ─────────────────────────────────────────────────────────
    "RC5-L": {
        "family": "RC",
        "label": "Precast RC frame, low ERD",
        "vc_prior": {"A": 0.133, "B": 0.267, "C": 0.400, "D": 0.200, "E": 0.000, "F": 0.000},
        "vc_most_likely": "C", "vc_range_min": "A", "vc_range_max": "D",
        "doc": "Precast frame without seismic design. Connection quality uncertain.",
    },
    "RC5-M": {
        "family": "RC",
        "label": "Precast RC frame, moderate ERD",
        "vc_prior": {"A": 0.000, "B": 0.133, "C": 0.267, "D": 0.400, "E": 0.200, "F": 0.000},
        "vc_most_likely": "D", "vc_range_min": "B", "vc_range_max": "E",
        "doc": "Precast frame with moderate seismic design.",
    },
    "RC6-L": {
        "family": "RC",
        "label": "Precast RC wall or dual system, low ERD",
        "vc_prior": {"A": 0.000, "B": 0.250, "C": 0.500, "D": 0.250, "E": 0.000, "F": 0.000},
        "vc_most_likely": "C", "vc_range_min": "B", "vc_range_max": "D",
        "doc": "Precast wall/dual without seismic design.",
    },
    "RC6-M": {
        "family": "RC",
        "label": "Precast RC wall or dual system, moderate ERD",
        "vc_prior": {"A": 0.000, "B": 0.000, "C": 0.250, "D": 0.500, "E": 0.250, "F": 0.000},
        "vc_most_likely": "D", "vc_range_min": "C", "vc_range_max": "E",
        "doc": "Precast wall/dual with moderate seismic design.",
    },

    # ── STEEL ────────────────────────────────────────────────────────────────
    "S-L": {
        "family": "STEEL",
        "label": "Steel frame, low ERD / no seismic design",
        "vc_prior": {"A": 0.000, "B": 0.000, "C": 0.200, "D": 0.400, "E": 0.267, "F": 0.133},
        "vc_most_likely": "D", "vc_range_min": "C", "vc_range_max": "F",
        "doc": "Steel frame without seismic design. IMS expanded range to B (non-ERD).",
    },
    "S-M/H": {
        "family": "STEEL",
        "label": "Steel frame, moderate or high ERD",
        "vc_prior": {"A": 0.000, "B": 0.000, "C": 0.000, "D": 0.250, "E": 0.500, "F": 0.250},
        "vc_most_likely": "E", "vc_range_min": "D", "vc_range_max": "F",
        "doc": "Steel frame with seismic design. IMS: D–F.",
    },

    # ── TIMBER ───────────────────────────────────────────────────────────────
    "T1": {
        "family": "TIMBER",
        "label": "Traditional / heavy timber",
        "vc_prior": {"A": 0.000, "B": 0.250, "C": 0.500, "D": 0.250, "E": 0.000, "F": 0.000},
        "vc_most_likely": "C", "vc_range_min": "B", "vc_range_max": "D",
        "doc": "Heavy wood, wattle and daub, bamboo. IMS: B–D.",
    },
    "T2-L": {
        "family": "TIMBER",
        "label": "Light timber frame, low ERD",
        "vc_prior": {"A": 0.000, "B": 0.133, "C": 0.267, "D": 0.400, "E": 0.200, "F": 0.000},
        "vc_most_likely": "D", "vc_range_min": "B", "vc_range_max": "E",
        "doc": "Light wood frame without seismic design.",
    },
    "T2-M/H": {
        "family": "TIMBER",
        "label": "Light timber frame, moderate or high ERD",
        "vc_prior": {"A": 0.000, "B": 0.000, "C": 0.000, "D": 0.250, "E": 0.500, "F": 0.250},
        "vc_most_likely": "E", "vc_range_min": "D", "vc_range_max": "F",
        "doc": "Light wood frame with seismic design. IMS: can reach F.",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# A2 — DUCTILITY / CODE LEVEL MAPPING
# ─────────────────────────────────────────────────────────────────────────────
# Maps (code_level_token, ductility_token) → ERD level and ERD score [0, 1].
#
# Tokens actually found in data:
#   Code level : CDL (low code), CDM (moderate code)
#   Ductility  : DUL (low ductility), DUM (moderate ductility), DNO (non-ductile)
#   Standard GEM: DUC (ductile), DBD (base-isolated), DU99 (unknown)
#
# ERD level is used for EMS type template filling (RC1-{erd}).
# ERD score (0-1) drives age modifier interaction and uncertainty.
# Key is (code_token_or_None, ductility_token_or_None).
# Engine tries (code, duct) first, then (code, None), then (None, duct).
# ─────────────────────────────────────────────────────────────────────────────
DUCTILITY_MAP: Dict[Tuple, Dict[str, Any]] = {
    # Combined tokens (code level + ductility) — most informative
    ("CDL", "DUL"): {"erd": "L",  "erd_score": 0.10, "label": "low-code, low-ductility"},
    ("CDL", "DUM"): {"erd": "L",  "erd_score": 0.25, "label": "low-code, med-ductility"},
    ("CDL", "DNO"): {"erd": "L",  "erd_score": 0.05, "label": "low-code, non-ductile"},
    ("CDM", "DUL"): {"erd": "M",  "erd_score": 0.40, "label": "mod-code, low-ductility"},
    ("CDM", "DUM"): {"erd": "M",  "erd_score": 0.55, "label": "mod-code, med-ductility"},
    ("CDM", "DNO"): {"erd": "L",  "erd_score": 0.20, "label": "mod-code, non-ductile"},
    # Code level only (no ductility token)
    ("CDL", None):  {"erd": "L",  "erd_score": 0.15, "label": "low-code only"},
    ("CDM", None):  {"erd": "M",  "erd_score": 0.50, "label": "mod-code only"},
    # Standard GEM ductility tokens (no code level token)
    (None,  "DNO"): {"erd": "L",  "erd_score": 0.05, "label": "non-ductile (GEM)"},
    (None,  "DUC"): {"erd": "H",  "erd_score": 0.90, "label": "ductile (GEM)"},
    (None,  "DBD"): {"erd": "H",  "erd_score": 1.00, "label": "base-isolated (GEM)"},
    (None,  "DU99"):{"erd": "L",  "erd_score": 0.10, "label": "ductility unknown"},
    # Unknown / missing
    (None,  None):  {"erd": "L",  "erd_score": 0.10, "label": "no ductility info"},
}

# ─────────────────────────────────────────────────────────────────────────────
# A3 — MATERIAL AND TOKEN ALIASES
# ─────────────────────────────────────────────────────────────────────────────
# Handles non-standard shorthand tokens found in real data.
# Add new aliases here as they are discovered in exposure datasets.
# ─────────────────────────────────────────────────────────────────────────────
MATERIAL_ALIASES: Dict[str, str] = {
    "ST":   "ST99",    # stone shorthand → stone unknown
    "CL":   "CL99",    # clay unit shorthand → clay unit unknown
    "UNK":  "MAT99",   # unknown material
    "MATO": "MATO",    # other material — kept as-is, maps to MATO family
}

# All valid GEM material L1 tokens (from GEM v2.0 Appendix A, Table 2)
MATERIAL_L1_TOKENS = {
    "MAT99", "C99", "CU", "CR", "SRC",
    "S", "S99", "SL", "SR", "SO",
    "ME", "ME99", "MEIR", "MEO",
    "M99", "MUR", "MCF", "MR", "MO",
    "E99", "EU", "ER",
    "W", "W99", "WHE", "WLI", "WS", "WWD", "WBB", "WO",
    "MATO",
}

# GEM masonry L2 unit technology tokens
MASONRY_UNIT_TOKENS = {
    "MUN99", "ADO",
    "ST99", "STRUB", "STDRE",
    "CL99", "CLBRS", "CLBRH", "CLBLH",
    "CB99", "CBS", "CBH",
    "MO",
}

# GEM masonry L2 reinforcement tokens
MASONRY_REINF_TOKENS = {
    "MR99", "RS", "RW", "RB", "RCM", "RCB",
}

# Masonry L3 mortar tokens
MORTAR_TOKENS = {
    "MO99", "MON", "MOM", "MOL", "MOC", "MOCL",
}

# Masonry L3 stone type tokens
STONE_TYPE_TOKENS = {
    "SP99", "SPLI", "SPSA", "SPTU", "SPSL", "SPGR", "SPBA", "SPO",
}

# GEM LLRS system L1 tokens (Table 3)
SYSTEM_L1_TOKENS = {
    "L99", "LN", "LFM", "LFINF", "LFBR", "LPB",
    "LWAL", "LDUAL", "LFLS", "LFLSINF", "LH", "LO",
}

# GEM ductility tokens (LLRS L2)
CODE_LEVEL_TOKENS  = {"CDL", "CDM", "CDH"}
DUCTILITY_TOKENS   = {"DUL", "DUM", "DNO", "DUC", "DBD", "DU99"}

# GEM irregularity tokens
IRREG_L1_TOKENS = {"IR99", "IRRE", "IRIR"}
IRREG_L2_TOKENS = {"IRPP", "IRPS", "IRVP", "IRVS"}
IRREG_L3_TOKENS = {"IRN", "TOR", "REC", "IRHO", "SOS", "CRW", "SHC", "POP", "SET", "CHV", "IRVO"}

# GEM occupancy L1 tokens
OCCUPANCY_L1_TOKENS = {"OC99","RES","COM","MIX","IND","AGR","ASS","GOV","EDU","OCO"}

# GEM building position tokens
POSITION_TOKENS = {"BP99", "BPD", "BP1", "BP2", "BP3"}

# GEM plan shape tokens
PLAN_SHAPE_TOKENS = {
    "PLF99","PLFSQ","PLFSQO","PLFR","PLFRO","PLFL","PLFC","PLFCO",
    "PLFD","PLFDO","PLFP","PLFPO","PLFE","PLFH","PLFS","PLFT",
    "PLFU","PLFX","PLFY","PLFI",
}

# GEM exterior wall tokens
EW_TOKENS = {"EW99","EWC","EWG","EWE","EWMA","EWME","EWV","EWW","EWSL","EWPL","EWCB","EWO"}

# GEM roof shape tokens (Level 1)
ROOF_SHAPE_TOKENS = {
    "RSH99","RSH1","RSH2","RSH3","RSH4","RSH5","RSH6","RSH7","RSH8","RSH9","RSHO",
}
# GEM roof covering tokens (Level 2)
ROOF_COVERING_TOKENS = {
    "RMT99","RMN","RMT1","RMT2","RMT3","RMT4","RMT5","RMT6",
    "RMT7","RMT8","RMT9","RMT10","RMT11","RMTO",
}
# GEM roof system material tokens (Level 3 — prefix match)
ROOF_SYSTEM_PREFIXES = ("RM", "RE", "RC", "RME", "RWO", "RFA", "RO", "R99")

# GEM floor material tokens (Level 1 prefix)
FLOOR_PREFIXES = ("FM", "FE", "FC", "FME", "FW", "FO", "FN", "F99")
FLOOR_CONN_TOKENS = {"FWC99", "FWCN", "FWCP"}

# GEM roof connection tokens
ROOF_CONN_TOKENS = {"RWC99", "RWCN", "RWCP", "RTD99", "RTDN", "RTDP"}

# GEM foundation tokens
FOUNDATION_TOKENS = {"FOS99", "FOSSL", "FOSN", "FOSDL", "FOSDN", "FOSO"}

# GEM height above-ground key tokens
HEIGHT_AG_KEYS = {"H", "HBET", "HEX", "HAPP"}
# GEM year key tokens
YEAR_KEYS = {"YEX", "YBET", "YPRE", "YAPP", "Y99"}

# ─────────────────────────────────────────────────────────────────────────────
# A4 — EMS TYPE ASSIGNMENT RULES
# ─────────────────────────────────────────────────────────────────────────────
# Ordered list of rules.  Engine evaluates top-to-bottom and uses the FIRST
# matching rule.  Lower "priority" number = evaluated earlier.
#
# Rule keys:
#   id          : unique string identifier
#   priority    : int — evaluation order (lower = first)
#   if          : dict of conditions (ALL must be true — AND logic)
#   then        : dict — what to assign:
#                   family      : sets material family
#                   ems_type    : deterministic single EMS type
#                   ems_template: template like "RC1-{erd}" filled from parsed.erd
#                   fallback    : key into FALLBACK_PRIORS for probabilistic assignment
#   confidence_penalty : float — multiplied into base confidence when rule fires
#   doc         : explanation string
#
# Condition keys in "if":
#   material_any         : parsed.material OR parsed.material_L2 contains any of list
#   material_L2_any      : parsed.material_L2 contains any of list
#   system_any           : parsed.system in list
#   family               : derived family equals string
#   missing_any          : any of list is missing from parsed (None or empty)
#
# To add a new rule: copy an existing entry, change id/priority/if/then.
# Priority 10–19  = family assignment from material
# Priority 20–29  = specific masonry sub-types
# Priority 30–39  = RC system rules
# Priority 50–59  = steel sub-types
# Priority 60–69  = timber sub-types
# Priority 70–89  = family-level fallbacks
# Priority 999    = global failsafe
# ─────────────────────────────────────────────────────────────────────────────
EMS_TYPE_RULES: List[Dict[str, Any]] = [

    # ── FAMILY ASSIGNMENT ────────────────────────────────────────────────────
    {"id": "MAT_RC",       "priority": 10,
     "if":   {"material_any": ["CR", "SRC"]},
     "then": {"family": "RC"},
     "confidence_penalty": 1.00,
     "doc": "CR (reinforced concrete) and SRC (composite) → RC family."},

    {"id": "MAT_RC_UNCERTAIN", "priority": 11,
     "if":   {"material_any": ["C99", "CU"]},
     "then": {"family": "RC"},
     "confidence_penalty": 0.75,
     "doc": "C99/CU (concrete unknown/unreinforced) → RC family with lower confidence."},

    {"id": "MAT_MASONRY",  "priority": 10,
     "if":   {"material_any": ["MUR", "MR", "MCF", "M99", "MUN99"]},
     "then": {"family": "MASONRY"},
     "confidence_penalty": 1.00,
     "doc": "Standard masonry material tokens → MASONRY family."},

    {"id": "MAT_EARTH",    "priority": 10,
     "if":   {"material_any": ["EU", "ER", "E99", "ET99", "ETR", "ETC", "ETO"]},
     "then": {"family": "MASONRY"},
     "confidence_penalty": 0.85,
     "doc": "Earth materials (rammed earth, cob) → MASONRY family (maps to M2)."},

    {"id": "MAT_STEEL",    "priority": 10,
     "if":   {"material_any": ["S", "S99", "SL", "SR", "SO", "ME", "ME99", "MEIR", "MEO"]},
     "then": {"family": "STEEL"},
     "confidence_penalty": 1.00,
     "doc": "Steel and metal tokens → STEEL family."},

    {"id": "MAT_TIMBER",   "priority": 10,
     "if":   {"material_any": ["W", "W99", "WHE", "WLI", "WS", "WWD", "WBB", "WO"]},
     "then": {"family": "TIMBER"},
     "confidence_penalty": 1.00,
     "doc": "Wood material tokens → TIMBER family."},

    {"id": "MAT_OTHER",    "priority": 12,
     "if":   {"material_any": ["MATO"]},
     "then": {"family": "RC"},
     "confidence_penalty": 0.50,
     "doc": "MATO (other material) → RC family as conservative fallback."},

    # ── MASONRY SPECIFIC TYPES ───────────────────────────────────────────────
    {"id": "MAS_REINF_OR_CONFINED", "priority": 15,
     "if":   {"family": "MASONRY", "material_any": ["MR", "MCF"]},
     "then": {"ems_type": "M7"},
     "confidence_penalty": 0.95,
     "doc": "Reinforced (MR) or confined (MCF) masonry → M7."},

    {"id": "MAS_ADOBE",    "priority": 16,
     "if":   {"family": "MASONRY", "material_L2_any": ["ADO"]},
     "then": {"ems_type": "M2"},
     "confidence_penalty": 0.95,
     "doc": "Adobe blocks (ADO) → M2."},

    {"id": "MAS_EARTH",    "priority": 17,
     "if":   {"family": "MASONRY", "material_any": ["EU", "ER", "E99", "ET99", "ETR", "ETC", "ETO"]},
     "then": {"fallback": "EARTH_MASONRY"},
     "confidence_penalty": 0.80,
     "doc": "Earth materials → M2/M5 distribution."},

    {"id": "MAS_RUBBLE",   "priority": 20,
     "if":   {"family": "MASONRY", "material_L2_any": ["STRUB"]},
     "then": {"ems_type": "M1"},
     "confidence_penalty": 0.90,
     "doc": "Rubble/fieldstone (STRUB) → M1."},

    {"id": "MAS_DRESSED_STONE", "priority": 21,
     "if":   {"family": "MASONRY", "material_L2_any": ["STDRE"]},
     "then": {"fallback": "STONE_DRESSED"},
     "confidence_penalty": 0.85,
     "doc": "Dressed stone (STDRE) → M3/M4 distribution."},

    {"id": "MAS_STONE_UNKNOWN", "priority": 22,
     "if":   {"family": "MASONRY",
              "material_L2_any": ["ST99","SP99","SPO","SPLI","SPSA","SPTU","SPSL","SPGR","SPBA"]},
     "then": {"fallback": "STONE_UNKNOWN"},
     "confidence_penalty": 0.80,
     "doc": "Unknown stone type (ST99, SP*) → M1/M3/M4 distribution."},

    {"id": "MAS_BRICK",    "priority": 23,
     "if":   {"family": "MASONRY", "material_L2_any": ["CL99","CLBRS","CLBRH","CLBLH"]},
     "then": {"fallback": "BRICK_MASONRY"},
     "confidence_penalty": 0.85,
     "doc": "Fired-clay brick/block → M5/M6 distribution."},

    {"id": "MAS_CONCRETE_BLOCK", "priority": 24,
     "if":   {"family": "MASONRY", "material_L2_any": ["CB99","CBS","CBH"]},
     "then": {"fallback": "CONCRETE_BLOCK_MASONRY"},
     "confidence_penalty": 0.80,
     "doc": "Concrete block masonry → M5/M6/M7 distribution."},

    # ── RC SYSTEM RULES ──────────────────────────────────────────────────────
    {"id": "RC_PRECAST_FRAME", "priority": 28,
     "if":   {"family": "RC", "material_L2_any": ["PC", "PCPS"],
              "system_any": ["LFM", "LFINF", "LFBR", "LPB", "LDUAL", "LH", "L99"]},
     "then": {"ems_template": "RC5-{erd}"},
     "confidence_penalty": 0.88,
     "doc": "Precast RC (PC/PCPS) with frame system → RC5-{erd}."},

    {"id": "RC_PRECAST_WALL", "priority": 29,
     "if":   {"family": "RC", "material_L2_any": ["PC", "PCPS"],
              "system_any": ["LWAL", "LFLS", "LFLSINF"]},
     "then": {"ems_template": "RC6-{erd}"},
     "confidence_penalty": 0.88,
     "doc": "Precast RC with wall/slab system → RC6-{erd}."},

    {"id": "RC_FLATSLAB",  "priority": 30,
     "if":   {"family": "RC", "system_any": ["LFLS", "LFLSINF"]},
     "then": {"ems_type": "RC4"},
     "confidence_penalty": 0.90,
     "doc": "Flat slab/waffle slab → RC4."},

    {"id": "RC_FRAME",     "priority": 31,
     "if":   {"family": "RC", "system_any": ["LFM", "LFINF", "LFBR", "LPB"]},
     "then": {"ems_template": "RC1-{erd}"},
     "confidence_penalty": 0.95,
     "doc": "RC frame systems (moment, infilled, braced, post-and-beam) → RC1-{erd}."},

    {"id": "RC_WALL",      "priority": 32,
     "if":   {"family": "RC", "system_any": ["LWAL"]},
     "then": {"ems_template": "RC2-{erd}"},
     "confidence_penalty": 0.95,
     "doc": "RC wall system → RC2-{erd}."},

    {"id": "RC_DUAL",      "priority": 33,
     "if":   {"family": "RC", "system_any": ["LDUAL"]},
     "then": {"ems_template": "RC3-{erd}"},
     "confidence_penalty": 0.95,
     "doc": "RC dual frame-wall system → RC3-{erd}."},

    {"id": "RC_NO_SYSTEM", "priority": 70,
     "if":   {"family": "RC", "missing_any": ["system"]},
     "then": {"fallback": "RC_missing_system"},
     "confidence_penalty": 0.75,
     "doc": "RC material known but system unknown → RC distribution."},

    {"id": "RC_UNCERTAIN_MATERIAL", "priority": 75,
     "if":   {"family": "RC", "material_any": ["C99", "CU", "MATO"]},
     "then": {"fallback": "RC_uncertain_material"},
     "confidence_penalty": 0.65,
     "doc": "Concrete with unknown reinforcement → conservative RC distribution."},

    # ── STEEL RULES ──────────────────────────────────────────────────────────
    {"id": "STEEL_LIGHT",  "priority": 50,
     "if":   {"family": "STEEL", "material_any": ["SL"]},
     "then": {"fallback": "STEEL_light"},
     "confidence_penalty": 0.80,
     "doc": "Cold-formed/light steel (SL) → heavier weight on S-L."},

    {"id": "STEEL_HEAVY",  "priority": 51,
     "if":   {"family": "STEEL", "material_any": ["SR"]},
     "then": {"fallback": "STEEL_heavy"},
     "confidence_penalty": 0.85,
     "doc": "Hot-rolled steel (SR) → heavier weight on S-M/H."},

    {"id": "STEEL_DEFAULT", "priority": 80,
     "if":   {"family": "STEEL"},
     "then": {"fallback": "STEEL_default"},
     "confidence_penalty": 0.70,
     "doc": "Steel family fallback when member type unknown."},

    # ── TIMBER RULES ─────────────────────────────────────────────────────────
    {"id": "TIMBER_WATTLE", "priority": 60,
     "if":   {"family": "TIMBER", "material_any": ["WWD", "WBB"]},
     "then": {"fallback": "TIMBER_traditional"},
     "confidence_penalty": 0.80,
     "doc": "Wattle-and-daub / bamboo → traditional timber."},

    {"id": "TIMBER_LIGHT", "priority": 61,
     "if":   {"family": "TIMBER", "material_any": ["WLI"]},
     "then": {"fallback": "TIMBER_modern"},
     "confidence_penalty": 0.85,
     "doc": "Light wood members (WLI) → modern timber."},

    {"id": "TIMBER_HEAVY", "priority": 62,
     "if":   {"family": "TIMBER", "material_any": ["WHE", "WS"]},
     "then": {"fallback": "TIMBER_traditional"},
     "confidence_penalty": 0.85,
     "doc": "Heavy/solid wood → traditional timber."},

    {"id": "TIMBER_DEFAULT", "priority": 81,
     "if":   {"family": "TIMBER"},
     "then": {"fallback": "TIMBER_default"},
     "confidence_penalty": 0.70,
     "doc": "Timber family fallback."},

    # ── MASONRY FALLBACK ─────────────────────────────────────────────────────
    {"id": "MAS_DEFAULT",  "priority": 85,
     "if":   {"family": "MASONRY"},
     "then": {"fallback": "MASONRY_default"},
     "confidence_penalty": 0.65,
     "doc": "Masonry family fallback when unit type and reinforcement are unknown."},

    # ── GLOBAL FAILSAFE ──────────────────────────────────────────────────────
    {"id": "FAILSAFE",     "priority": 999,
     "if":   {},
     "then": {"ems_type": "M4"},
     "confidence_penalty": 0.20,
     "doc": "Global failsafe — no rule matched. Returns M4 (conservative stone masonry)."},
]

# ─────────────────────────────────────────────────────────────────────────────
# A5 — FALLBACK PRIORS
# ─────────────────────────────────────────────────────────────────────────────
# Used when a rule fires "fallback": "<key>".
# Each entry is a list of [ems_type, weight] pairs.  Weights are normalised.
# To add a new distribution: add a new key with a list of [type, weight] pairs.
# ─────────────────────────────────────────────────────────────────────────────
FALLBACK_PRIORS: Dict[str, List[List[Any]]] = {
    "MASONRY_default":       [["M3", 0.35], ["M4", 0.35], ["M5", 0.30]],
    "STONE_UNKNOWN":         [["M1", 0.40], ["M3", 0.40], ["M4", 0.20]],
    "STONE_DRESSED":         [["M3", 0.70], ["M4", 0.30]],
    "BRICK_MASONRY":         [["M5", 0.60], ["M6", 0.40]],
    "CONCRETE_BLOCK_MASONRY":[["M5", 0.55], ["M6", 0.30], ["M7", 0.15]],
    "EARTH_MASONRY":         [["M2", 0.80], ["M5", 0.20]],
    "RC_missing_system":     [["RC1-L", 0.45], ["RC2-L", 0.35], ["RC3-L", 0.20]],
    "RC_uncertain_material": [["RC1-L", 0.40], ["RC2-L", 0.35], ["RC3-L", 0.25]],
    "STEEL_default":         [["S-L",   0.40], ["S-M/H", 0.60]],
    "STEEL_light":           [["S-L",   0.70], ["S-M/H", 0.30]],
    "STEEL_heavy":           [["S-L",   0.30], ["S-M/H", 0.70]],
    "TIMBER_default":        [["T1",    0.10], ["T2-L",  0.40], ["T2-M/H", 0.50]],
    "TIMBER_traditional":    [["T1",    0.60], ["T2-L",  0.25], ["T2-M/H", 0.15]],
    "TIMBER_modern":         [["T2-L",  0.45], ["T2-M/H", 0.55]],
}

# Confidence rubric — base confidence from attribute completeness
CONFIDENCE_RUBRIC: Dict[str, float] = {
    "material+system+height+erd": 0.95,
    "material+system+height":     0.80,
    "material+height":            0.60,
    "material":                   0.40,
    "partial":                    0.20,
}

# ─────────────────────────────────────────────────────────────────────────────
# A6 — EXACT OVERRIDE RULES
# ─────────────────────────────────────────────────────────────────────────────
# When the full GEM string matches exactly, skip all rules and return this.
# Optionally force a specific VC class too.
#
# Keys per entry:
#   gem        : exact GEM string to match
#   ems_type   : forced EMS type
#   vc_class   : (optional) forced VC class letter — skips all modifiers too
#   confidence : override confidence (default 0.99)
#   doc        : explanation
# ─────────────────────────────────────────────────────────────────────────────
EXACT_OVERRIDES: List[Dict[str, Any]] = [
    # Examples — add verified building overrides here:
    # {
    #     "gem": "CR+CIP/LFM+CDM/H:5/IND",
    #     "ems_type": "RC1-M",
    #     "confidence": 0.99,
    #     "doc": "Verified RC moment frame, cast-in-place, moderate ERD, 5 storeys.",
    # },
    # {
    #     "gem": "MUR+STRUB/LWAL+DNO/H:1/IND",
    #     "ems_type": "M1",
    #     "vc_class": "A",
    #     "confidence": 0.99,
    #     "doc": "Verified rubble stone masonry, 1 storey — deterministic M1, VC=A.",
    # },
]

# ─────────────────────────────────────────────────────────────────────────────
# A7 — VC MODIFIER RULES
# ─────────────────────────────────────────────────────────────────────────────
# Applied AFTER EMS type assignment to shift the VC distribution.
# Shift > 0 → more vulnerable (toward A).  Shift < 0 → less vulnerable (→ F).
# All modifiers in a list are evaluated; all that match fire simultaneously.
# Their shifts are SUMMED and then clamped to ±MAX_CUMULATIVE_SHIFT (see A8).
# The shift then cannot push mass beyond vc_range_min/vc_range_max in EMS_VOCAB.
#
# Rule keys:
#   id                 : unique string
#   doc                : explanation for team
#   if                 : dict of conditions (ALL must be true)
#   shift              : float — positive = more vulnerable, negative = less
#   confidence_penalty : float [0,1] — multiplied into final confidence
#   max_contribution   : (optional) float — cap this rule's contribution
#
# Condition keys:
#   family_is              : parsed.family == value
#   family_in              : parsed.family in list
#   material_is            : parsed.material == value
#   material_any           : parsed.material OR material_L2 contains any of list
#   material_L2_any        : parsed.material_L2 contains any of list
#   material_L3_any        : parsed.material_L3 contains any of list
#   system_is              : parsed.system == value
#   system_any             : parsed.system in list
#   infill_any             : parsed.infill_material contains any of list
#   erd_is                 : parsed.erd == value  (L / M / H)
#   erd_score_below        : parsed.erd_score < value
#   erd_score_above        : parsed.erd_score >= value
#   ductility_token_is     : parsed.ductility_token == value
#   ductility_token_in     : parsed.ductility_token in list
#   code_level_is          : parsed.code_level == value
#   height_bin_is          : parsed.height_bin == value  (L / M / H)
#   height_bin_in          : parsed.height_bin in list
#   height_stories_above   : parsed.height_stories (int) > value
#   year_before            : parsed.year_value < value
#   year_after_eq          : parsed.year_value >= value
#   year_known             : parsed.year_value is not None (True/False)
#   occupancy_L1_is        : parsed.occupancy == value
#   occupancy_detail_in    : parsed.occupancy_detail in list
#   position_in            : parsed.position in list
#   plan_shape_in          : parsed.plan_shape in list
#   irregularity_L1_is     : parsed.irregularity_L1 == value
#   irregularity_plan_type_in   : parsed.irregularity_plan_types contains any
#   irregularity_vert_type_in   : parsed.irregularity_vert_types contains any
#   roof_covering_in       : parsed.roof_covering in list
#   roof_system_in         : parsed.roof_system_material starts with any prefix in list
#   floor_material_in      : parsed.floor_material starts with any prefix in list
#   floor_conn_is          : parsed.floor_connection == value
#   roof_conn_in           : parsed.roof_connections contains any of list
#   foundation_in          : parsed.foundation in list
#   exterior_wall_any      : parsed.exterior_walls contains any of list
#   ems_type_in            : final ems_type in list
#
# Note: Multiple conditions within one rule are ANDed.
# For OR logic within one attribute: use a list (e.g. material_any).
# For separate OR branches: define two separate rules.
#
# ─────────────────────────────────────────────────────────────────────────────
VC_MODIFIERS: List[Dict[str, Any]] = [

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 1 — STRUCTURAL IRREGULARITY
    # Source: IMS-25 explicitly names these as VC-shifting factors.
    # ══════════════════════════════════════════════════════════════════════════

    {   "id": "IRREG_SOFT_STOREY",
        "doc": "Soft storey (SOS) — primary vertical irregularity. "
               "Concentrates inter-storey drift; documented failure in virtually every major earthquake.",
        "if":  {"irregularity_vert_type_in": ["SOS"]},
        "shift": +1.00, "confidence_penalty": 0.88,
    },
    {   "id": "IRREG_SHORT_COLUMN",
        "doc": "Short column (SHC) — brittle shear failure; well-documented failure mode.",
        "if":  {"irregularity_vert_type_in": ["SHC"]},
        "shift": +0.75, "confidence_penalty": 0.88,
    },
    {   "id": "IRREG_CRIPPLE_WALL",
        "doc": "Cripple wall (CRW) — low lateral stiffness at ground level.",
        "if":  {"irregularity_vert_type_in": ["CRW"]},
        "shift": +0.75, "confidence_penalty": 0.88,
    },
    {   "id": "IRREG_LARGE_OVERHANG",
        "doc": "Large overhang / change in vertical structure (CHV).",
        "if":  {"irregularity_vert_type_in": ["CHV"]},
        "shift": +0.50, "confidence_penalty": 0.90,
    },
    {   "id": "IRREG_POUNDING",
        "doc": "Pounding potential (POP) — floor-level mismatch with adjacent buildings.",
        "if":  {"irregularity_vert_type_in": ["POP"]},
        "shift": +0.50, "confidence_penalty": 0.90,
    },
    {   "id": "IRREG_SETBACK",
        "doc": "Setback (SET) — discontinuity in load path at setback level.",
        "if":  {"irregularity_vert_type_in": ["SET"]},
        "shift": +0.25, "confidence_penalty": 0.93,
    },
    {   "id": "IRREG_TORSION",
        "doc": "Torsion eccentricity in plan (TOR) — increases demands on one side.",
        "if":  {"irregularity_plan_type_in": ["TOR"]},
        "shift": +0.50, "confidence_penalty": 0.90,
    },
    {   "id": "IRREG_REENTRANT_CORNER",
        "doc": "Re-entrant corner (REC) — stress concentration at corner.",
        "if":  {"irregularity_plan_type_in": ["REC"]},
        "shift": +0.25, "confidence_penalty": 0.93,
    },
    {   "id": "IRREG_IRIR_GENERIC",
        "doc": "Building flagged as irregular (IRIR) but irregularity type unknown. "
               "Conservative mild precaution.",
        "if":  {"irregularity_L1_is": "IRIR",
                "irregularity_plan_type_in": [],   # fires only when no specific plan type
                "irregularity_vert_type_in": []},  # and no specific vert type known
        "shift": +0.25, "confidence_penalty": 0.93,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 2 — PLAN SHAPE
    # Geometric irregularity increases torsional eccentricity.
    # Source: IMS-25; FEMA 154 irregular plan penalty.
    # ══════════════════════════════════════════════════════════════════════════

    {   "id": "PLAN_COMPLEX_SHAPE",
        "doc": "Non-rectangular plan shape (L, E, H, S, T, U, X, Y, irregular) "
               "— torsional eccentricity, stress concentrations.",
        "if":  {"plan_shape_in": ["PLFL","PLFE","PLFH","PLFS","PLFT","PLFU","PLFX","PLFY","PLFI",
                                   "PLFD","PLFDO","PLFP","PLFPO","PLFC","PLFCO"]},
        "shift": +0.25, "confidence_penalty": 0.93,
    },
    {   "id": "PLAN_WITH_OPENING",
        "doc": "Square or rectangular plan with interior opening — partial diaphragm.",
        "if":  {"plan_shape_in": ["PLFSQO", "PLFRO"]},
        "shift": +0.25, "confidence_penalty": 0.93,
    },
    {   "id": "PLAN_REGULAR_BONUS",
        "doc": "Simple square or rectangular plan (no opening) — no geometric penalty.",
        "if":  {"plan_shape_in": ["PLFSQ", "PLFR"]},
        "shift": -0.25, "confidence_penalty": 1.00,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 3 — AGE / CONSTRUCTION ERA
    # Source: IMS-25 Section 3.7; seismic code development history.
    # Only one age bracket fires (mutually exclusive via year conditions).
    # Baseline = post-1990 (no shift). Brackets are relative to that.
    # ══════════════════════════════════════════════════════════════════════════

    {   "id": "AGE_PRE1920",
        "doc": "Built before 1920 — pre-any-seismic-consideration era globally. "
               "No seismic code anywhere.",
        "if":  {"year_known": True, "year_before": 1920},
        "shift": +1.25, "confidence_penalty": 0.85, "max_contribution": 1.25,
    },
    {   "id": "AGE_1920_1945",
        "doc": "1920–1944: very early seismic codes, mostly unreinforced or poorly reinforced.",
        "if":  {"year_known": True, "year_after_eq": 1920, "year_before": 1945},
        "shift": +0.75, "confidence_penalty": 0.88, "max_contribution": 0.75,
    },
    {   "id": "AGE_1945_1970",
        "doc": "1945–1969: post-war reconstruction, codes developing but inconsistently applied.",
        "if":  {"year_known": True, "year_after_eq": 1945, "year_before": 1970},
        "shift": +0.50, "confidence_penalty": 0.90, "max_contribution": 0.50,
    },
    {   "id": "AGE_1970_1990",
        "doc": "1970–1989: modern codes emerging, variable enforcement.",
        "if":  {"year_known": True, "year_after_eq": 1970, "year_before": 1990},
        "shift": +0.25, "confidence_penalty": 0.92, "max_contribution": 0.25,
    },
    # No rule for 1990–1999: this is the baseline (shift = 0)
    {   "id": "AGE_POST2000",
        "doc": "Built 2000 or later — post-2000 codes generally better enforced.",
        "if":  {"year_known": True, "year_after_eq": 2000},
        "shift": -0.25, "confidence_penalty": 1.00, "max_contribution": 0.25,
    },
    {   "id": "AGE_POST2010_DUCTILE",
        "doc": "Built 2010+ AND confirmed ductile detailing (DUC or DBD) — "
               "strongest combined evidence of modern seismic design.",
        "if":  {"year_known": True, "year_after_eq": 2010,
                "ductility_token_in": ["DUC", "DBD"]},
        "shift": -0.75, "confidence_penalty": 1.00, "max_contribution": 0.75,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 4 — DUCTILITY / ERD
    # Source: GEM ductility tokens; IMS-25 Section 3.7.
    # ══════════════════════════════════════════════════════════════════════════

    {   "id": "DUCTILITY_DNO",
        "doc": "Confirmed non-ductile structural system (DNO) — brittle failure expected.",
        "if":  {"ductility_token_in": ["DNO"]},
        "shift": +0.50, "confidence_penalty": 0.90,
    },
    {   "id": "DUCTILITY_DUC",
        "doc": "Confirmed ductile design (DUC) — capacity design principles applied.",
        "if":  {"ductility_token_in": ["DUC"]},
        "shift": -0.75, "confidence_penalty": 1.00,
    },
    {   "id": "DUCTILITY_DBD",
        "doc": "Base isolation or energy dissipation devices (DBD) — major vulnerability reduction.",
        "if":  {"ductility_token_in": ["DBD"]},
        "shift": -1.25, "confidence_penalty": 1.00,
    },
    {   "id": "HIGH_RISE_UNKNOWN_DUCTILITY",
        "doc": "High-rise (H bin, 8+ storeys) with no ductility information — precautionary.",
        "if":  {"height_bin_is": "H", "ductility_token_in": ["DU99"],
                "erd_score_below": 0.30},
        "shift": +0.50, "confidence_penalty": 0.88,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 5 — ROOF SYSTEM
    # Source: IMS-25 explicitly: "weight of roof is one of the important factors;
    # heavy roofs being a liability."  Well-documented in Turkey, Iran, Haiti.
    # ══════════════════════════════════════════════════════════════════════════

    {   "id": "ROOF_EARTHEN_ON_MASONRY",
        "doc": "Earthen roof covering (RMT9) on masonry — IMS explicitly flags this as "
               "very high risk. Primary collapse cause in Turkey 1999, Iran 2003, Haiti 2010.",
        "if":  {"roof_covering_in": ["RMT9"], "family_in": ["MASONRY"]},
        "shift": +1.50, "confidence_penalty": 0.88,
    },
    {   "id": "ROOF_EARTHEN_ON_TIMBER",
        "doc": "Earthen roof (RMT9) on timber frame — mass mismatch.",
        "if":  {"roof_covering_in": ["RMT9"], "family_in": ["TIMBER"]},
        "shift": +1.00, "confidence_penalty": 0.88,
    },
    {   "id": "ROOF_STONE_SLAB_ON_MASONRY",
        "doc": "Stone slab roof (RMT5) on masonry — extremely heavy mass.",
        "if":  {"roof_covering_in": ["RMT5"], "family_in": ["MASONRY"]},
        "shift": +1.00, "confidence_penalty": 0.88,
    },
    {   "id": "ROOF_MASONRY_VAULT",
        "doc": "Vaulted or arched masonry roof (RM1, RM2) — lateral thrust on walls.",
        "if":  {"roof_system_in": ["RM1", "RM2"], "family_in": ["MASONRY"]},
        "shift": +0.75, "confidence_penalty": 0.90,
    },
    {   "id": "ROOF_HEAVY_WOOD_ON_MASONRY",
        "doc": "Heavy wooden roof (RWO2 — beams/trusses with heavy covering) on masonry.",
        "if":  {"roof_system_in": ["RWO2"], "family_in": ["MASONRY"]},
        "shift": +0.50, "confidence_penalty": 0.90,
    },
    {   "id": "ROOF_THATCH_OR_BAMBOO",
        "doc": "Thatch/bamboo/straw roof (RWO5) — fragile, fire risk, poor connections.",
        "if":  {"roof_system_in": ["RWO5"]},
        "shift": +0.50, "confidence_penalty": 0.90,
    },
    {   "id": "ROOF_LIGHT_BENEFIT",
        "doc": "Light roof covering (metal/asbestos sheet RMT6, shingle RMT7, "
               "light wood RWO1/RWO4) — reduces inertial load.",
        "if":  {"roof_covering_in": ["RMT6", "RMT7"],
                "roof_system_in":   ["RWO1", "RWO4"]},
        "shift": -0.25, "confidence_penalty": 1.00,
    },
    {   "id": "ROOF_NO_TIEDOWN",
        "doc": "Roof-wall diaphragm connection not provided (RWCN) — roof detachment under shaking.",
        "if":  {"roof_conn_in": ["RWCN"]},
        "shift": +0.25, "confidence_penalty": 0.92,
    },
    {   "id": "ROOF_TIEDOWN_PRESENT",
        "doc": "Roof tie-down provided (RTDP) — anchors roof to wall structure.",
        "if":  {"roof_conn_in": ["RTDP"]},
        "shift": -0.25, "confidence_penalty": 1.00,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 6 — FLOOR DIAPHRAGM
    # Source: IMS-25 mentions floor flexibility; observed in L'Aquila 2009,
    # Christchurch 2011, Kahramanmaras 2023.
    # ══════════════════════════════════════════════════════════════════════════

    {   "id": "FLOOR_WOOD_ON_MASONRY",
        "doc": "Wood floor diaphragm (FW*) in masonry building — flexible diaphragm fails to "
               "redistribute lateral loads to walls. Classic URM vulnerability.",
        "if":  {"floor_material_in": ["FW"], "family_in": ["MASONRY"]},
        "shift": +0.75, "confidence_penalty": 0.90,
    },
    {   "id": "FLOOR_EARTHEN",
        "doc": "Earthen floor (FE*) — flexible, heavy, poor lateral load distribution.",
        "if":  {"floor_material_in": ["FE"]},
        "shift": +0.50, "confidence_penalty": 0.90,
    },
    {   "id": "FLOOR_PRECAST_NO_TOPPING",
        "doc": "Precast concrete floor without RC topping (FC4) — semi-flexible, "
               "connection quality uncertain.",
        "if":  {"floor_material_in": ["FC4"]},
        "shift": +0.25, "confidence_penalty": 0.92,
    },
    {   "id": "FLOOR_NOT_CONNECTED",
        "doc": "Floor-wall diaphragm connection not provided (FWCN).",
        "if":  {"floor_conn_is": "FWCN"},
        "shift": +0.50, "confidence_penalty": 0.88,
    },
    {   "id": "FLOOR_WELL_CONNECTED",
        "doc": "Floor-wall diaphragm connection present (FWCP) — good lateral load transfer.",
        "if":  {"floor_conn_is": "FWCP"},
        "shift": -0.25, "confidence_penalty": 1.00,
    },
    {   "id": "FLOOR_RC_RIGID",
        "doc": "Rigid RC diaphragm (FC1/FC2 — cast-in-place) — distributes loads effectively.",
        "if":  {"floor_material_in": ["FC1", "FC2"]},
        "shift": -0.25, "confidence_penalty": 1.00,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 7 — MASONRY MATERIAL QUALITY (mortar, reinforcement)
    # Source: Earthquake engineering knowledge; masonry construction literature.
    # ══════════════════════════════════════════════════════════════════════════

    {   "id": "MORTAR_NONE",
        "doc": "No mortar (MON) — dry-stacked masonry. Zero tensile bond; worst case.",
        "if":  {"material_L3_any": ["MON"]},
        "shift": +0.75, "confidence_penalty": 0.90,
    },
    {   "id": "MORTAR_MUD",
        "doc": "Mud mortar (MOM) — dissolves and weakens under cyclic loading.",
        "if":  {"material_L3_any": ["MOM"]},
        "shift": +0.50, "confidence_penalty": 0.90,
    },
    {   "id": "MORTAR_CEMENT",
        "doc": "Cement or cement-lime mortar (MOC/MOCL) — good bond strength.",
        "if":  {"material_L3_any": ["MOC", "MOCL"]},
        "shift": -0.25, "confidence_penalty": 1.00,
    },
    {   "id": "MASONRY_REINF_RC_BANDS",
        "doc": "RC tie beams / bond beams (RCB) in masonry — prevents storey collapse. "
               "Very significant improvement; observed in Turkey, Italy.",
        "if":  {"material_L2_any": ["RCB"]},
        "shift": -0.75, "confidence_penalty": 1.00,
    },
    {   "id": "MASONRY_REINF_STEEL",
        "doc": "Steel reinforcement (RS) in masonry — confined or reinforced masonry.",
        "if":  {"material_L2_any": ["RS"]},
        "shift": -0.50, "confidence_penalty": 1.00,
    },
    {   "id": "MASONRY_REINF_BAMBOO",
        "doc": "Bamboo reinforcement (RB) — limited seismic improvement.",
        "if":  {"material_L2_any": ["RB"]},
        "shift": -0.25, "confidence_penalty": 1.00,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 8 — BUILDING POSITION (pounding risk)
    # Source: IMS-25; earthquake engineering knowledge.
    # ══════════════════════════════════════════════════════════════════════════

    {   "id": "POSITION_CORNER",
        "doc": "Corner building — adjoining on three sides (BP3). "
               "Pounding from two directions; torsional eccentricity.",
        "if":  {"position_in": ["BP3"]},
        "shift": +0.50, "confidence_penalty": 0.92,
    },
    {   "id": "POSITION_END_ROW",
        "doc": "End-of-row building — adjoining on one side (BP1). "
               "Pounding on one side.",
        "if":  {"position_in": ["BP1"]},
        "shift": +0.25, "confidence_penalty": 0.93,
    },
    {   "id": "POSITION_DETACHED",
        "doc": "Detached building (BPD) — no pounding risk.",
        "if":  {"position_in": ["BPD"]},
        "shift": -0.25, "confidence_penalty": 1.00,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 9 — OCCUPANCY (consequence-based conservative shift)
    # Source: IMS-25; building importance factors in seismic codes.
    # ══════════════════════════════════════════════════════════════════════════

    {   "id": "OCC_CRITICAL_FACILITY",
        "doc": "Hospital/clinic (COM4) or emergency response government (GOV2) — "
               "critical post-earthquake function; apply conservative VC.",
        "if":  {"occupancy_detail_in": ["COM4", "GOV2"]},
        "shift": +0.50, "confidence_penalty": 0.95,
    },
    {   "id": "OCC_SCHOOL",
        "doc": "School (EDU2) or university (EDU3) — high daytime occupancy, children.",
        "if":  {"occupancy_detail_in": ["EDU2", "EDU3", "EDU4"]},
        "shift": +0.50, "confidence_penalty": 0.95,
    },
    {   "id": "OCC_LARGE_ASSEMBLY",
        "doc": "Arena (ASS2) or cinema/concert hall (ASS3) — high peak occupancy events.",
        "if":  {"occupancy_detail_in": ["ASS2", "ASS3"]},
        "shift": +0.25, "confidence_penalty": 0.95,
    },
    {   "id": "OCC_INFORMAL_HOUSING",
        "doc": "Informal housing (RES6) — typically non-engineered, self-built, "
               "poor quality control.",
        "if":  {"occupancy_detail_in": ["RES6"]},
        "shift": +0.50, "confidence_penalty": 0.90,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 10 — FOUNDATION
    # Source: earthquake engineering knowledge; soft-soil amplification research.
    # ══════════════════════════════════════════════════════════════════════════

    {   "id": "FOUND_DEEP_NO_LATERAL",
        "doc": "Deep foundation without lateral capacity (FOSDN) — poor seismic performance.",
        "if":  {"foundation_in": ["FOSDN"]},
        "shift": +0.50, "confidence_penalty": 0.90,
    },
    {   "id": "FOUND_SHALLOW_NO_LATERAL",
        "doc": "Shallow foundation without lateral capacity (FOSN).",
        "if":  {"foundation_in": ["FOSN"]},
        "shift": +0.25, "confidence_penalty": 0.92,
    },
    {   "id": "FOUND_SHALLOW_WITH_LATERAL",
        "doc": "Shallow foundation with lateral capacity (FOSSL) — baseline good.",
        "if":  {"foundation_in": ["FOSSL"]},
        "shift": -0.25, "confidence_penalty": 1.00,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 11 — EXTERIOR WALLS / INFILL
    # Source: Mediterranean earthquake experience; infill-RC interaction.
    # ══════════════════════════════════════════════════════════════════════════

    {   "id": "INFILL_MASONRY_ON_RC",
        "doc": "Masonry infill walls (EWMA) in RC frame — creates short column / "
               "soft storey potential. Very common in Mediterranean, Middle East, Turkey.",
        "if":  {"exterior_wall_any": ["EWMA"], "family_in": ["RC"]},
        "shift": +0.25, "confidence_penalty": 0.92,
    },
    {   "id": "INFILL_MASONRY_FROM_LFINF",
        "doc": "Infilled RC frame (LFINF) with masonry infill explicitly coded — "
               "same risk as EWMA on RC but identified from system token.",
        "if":  {"system_any": ["LFINF"], "infill_any": ["MUR","ADO","CBH","CBS","CLBRS","CLBRH"],
                "family_in": ["RC"]},
        "shift": +0.25, "confidence_penalty": 0.92,
    },
    {   "id": "INFILL_EARTHEN_ON_RC",
        "doc": "Earthen infill (EWE) in RC frame — very weak, large stiffness discontinuity.",
        "if":  {"exterior_wall_any": ["EWE"], "family_in": ["RC"]},
        "shift": +0.50, "confidence_penalty": 0.90,
    },
    {   "id": "WALL_CONCRETE_ON_RC",
        "doc": "Concrete exterior walls (EWC) on RC frame — adds lateral stiffness.",
        "if":  {"exterior_wall_any": ["EWC"], "family_in": ["RC"]},
        "shift": -0.25, "confidence_penalty": 1.00,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # GROUP 12 — PRECAST RC SPECIFIC
    # Source: earthquake engineering knowledge; Spitak 1988, Chi-Chi 1999.
    # ══════════════════════════════════════════════════════════════════════════

    {   "id": "PRECAST_NO_DUCTILITY_INFO",
        "doc": "Precast RC (RC5/RC6) without ductility information — "
               "connection quality historically variable; precautionary.",
        "if":  {"ems_type_in": ["RC5-L", "RC5-M", "RC6-L", "RC6-M"],
                "erd_score_below": 0.30},
        "shift": +0.50, "confidence_penalty": 0.88,
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# A8 — GLOBAL TUNING CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
MAX_CUMULATIVE_SHIFT   = 2.0   # Maximum total VC shift (sum of all modifiers)
ENTROPY_PENALTY_ALPHA  = 0.25  # How much EMS entropy penalises confidence
VC_ORDER = ["A", "B", "C", "D", "E", "F"]  # Vulnerability class order (A=most vulnerable)
VC_INT   = {"A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6}  # VC as integer


# ═══════════════════════════════════════════════════════════════════════════════
#  ZONE B — ENGINE
#  ─────────────────────────────────────────────────────────────────────────────
#  Do not edit unless extending the engine architecture itself.
# ═══════════════════════════════════════════════════════════════════════════════

def _entropy(probs: Sequence[float]) -> float:
    h = 0.0
    for p in probs:
        if p > 0:
            h -= p * math.log(p)
    return h

def _normalise(d: Dict[str, float]) -> Dict[str, float]:
    s = sum(max(0.0, v) for v in d.values())
    if s <= 0:
        return {k: 0.0 for k in d}
    return {k: max(0.0, v) / s for k, v in d.items()}

def _normalise_list(lst: List[float]) -> List[float]:
    s = sum(lst)
    if s <= 0:
        return [0.0] * len(lst)
    return [v / s for v in lst]

def _vc_credible_range(vc_probs: Dict[str, float], mass: float = 0.80) -> Tuple[str, str]:
    probs = [vc_probs.get(c, 0.0) for c in VC_ORDER]
    best = None
    for i in range(len(VC_ORDER)):
        s = 0.0
        for j in range(i, len(VC_ORDER)):
            s += probs[j]
            if s >= mass:
                cand = (j - i, i, j)
                if best is None or cand < best:
                    best = cand
                break
    if best is None:
        return ("A", "F")
    _, i, j = best
    return (VC_ORDER[i], VC_ORDER[j])

def _vc_mode(vc_probs: Dict[str, float]) -> str:
    return max(VC_ORDER, key=lambda k: vc_probs.get(k, 0.0))


@dataclass
class EmsCandidate:
    ems_type: str
    weight: float
    confidence: float
    rule_id: str
    rule_trace: List[str]
    flags: List[str]


@dataclass
class TranslationResult:
    """All output fields.  Backward-compatible with original translator_engine.py."""
    # Core (unchanged names)
    gem_str:              str
    parsed:               Dict[str, Any]
    ems_candidates:       List[Dict[str, Any]]
    vc_probs:             Dict[str, float]       # final (post-modifier)
    summary:              Dict[str, Any]
    uncertainty:          Dict[str, Any]
    confidence:           float
    warnings:             List[str]
    # VC class predictions
    vc_class:             str                    # final modal VC class letter
    vc_class_int:         int                    # final VC as integer (A=1..F=6)
    vc_class_base:        str                    # base modal VC (no modifiers)
    vc_class_base_int:    int                    # base VC as integer
    # Base distribution (new)
    vc_probs_base:        Dict[str, float]
    # Modifier trace (new)
    vc_modifiers_applied: List[Dict[str, Any]]


class GemParser:
    """Parses a GEM v2.0 taxonomy string into a structured feature dict."""

    # Tokens that look like material L1 but are actually occupancy
    _OCCUPANCY_PREFIXES = tuple(OCCUPANCY_L1_TOKENS)

    def parse(self, gem_str: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            # Core structural
            "material":           None,
            "material_L2":        [],
            "material_L3":        [],
            "material_all":       [],
            "system":             None,
            "system_L2":          [],
            "infill_material":    [],
            "erd":                "L",
            "erd_score":          0.10,
            "code_level":         None,
            "ductility_token":    None,
            # Height
            "height_stories":     None,
            "height_bin":         None,
            # Year
            "year_value":         None,
            "year_token_type":    None,
            # Secondary attributes
            "occupancy":          None,
            "occupancy_detail":   None,
            "directions":         [],
            "position":           None,
            "plan_shape":         None,
            "irregularity_L1":    None,
            "irregularity_plan_types":  [],
            "irregularity_vert_types":  [],
            "exterior_walls":     [],
            "roof_shape":         None,
            "roof_covering":      None,
            "roof_system_material": None,
            "roof_connections":   [],
            "floor_material":     None,
            "floor_connection":   None,
            "foundation":         None,
            # Derived
            "family":             None,
            # Raw
            "raw_blocks":         [],
        }

        # Pre-process: strip whitespace
        gem_str = gem_str.strip()
        blocks = [b for b in gem_str.split("/") if b.strip()]
        out["raw_blocks"] = blocks

        for block in blocks:
            self._parse_block(block, out)

        # Resolve ERD from ductility tokens
        self._resolve_erd(out)

        # Compute height_bin
        out["height_bin"] = self._height_bin(out["height_stories"])

        return out

    def _parse_block(self, block: str, out: Dict[str, Any]) -> None:
        """Route one slash-separated block to the correct parser."""

        # ── Infilled frame with parenthetical infill: LFINF(MUR+CBH)+CDL+DUL
        m_inf = re.match(r"^(LFINF|LFLSINF)\(([^)]+)\)(.*)$", block)
        if m_inf:
            system_tok = m_inf.group(1)
            infill_raw = m_inf.group(2)
            rest       = m_inf.group(3)
            if out["system"] is None:
                out["system"] = system_tok
            for itok in infill_raw.split("+"):
                tok = itok.strip()
                tok = MATERIAL_ALIASES.get(tok, tok)
                if tok:
                    out["infill_material"].append(tok)
            # Parse remaining tokens (ductility etc.) from rest
            if rest:
                rest_block = rest.lstrip("+")
                if rest_block:
                    self._parse_level_tokens(rest_block.split("+"), out)
            return

        # ── Direction block: DX or DY
        if block in ("DX", "DY", "D99"):
            out["directions"].append(block)
            return

        parts = [p.strip() for p in block.split("+") if p.strip()]
        if not parts:
            return
        head = parts[0]

        # ── Numeric key:value tokens (height, year)
        if ":" in head:
            self._parse_numeric(head, parts, out)
            return

        # ── Irregularity
        if head in IRREG_L1_TOKENS:
            out["irregularity_L1"] = head
            self._parse_irregularity(parts[1:], out)
            return

        # ── Plan shape
        if head in PLAN_SHAPE_TOKENS:
            out["plan_shape"] = head
            return

        # ── Building position
        if head in POSITION_TOKENS:
            out["position"] = head
            return

        # ── Exterior wall
        if head in EW_TOKENS:
            out["exterior_walls"].append(head)
            return

        # ── Foundation
        if head in FOUNDATION_TOKENS:
            out["foundation"] = head
            return

        # ── Floor diaphragm connection tokens
        if head in FLOOR_CONN_TOKENS:
            out["floor_connection"] = head
            return

        # ── Roof connection tokens
        if head in ROOF_CONN_TOKENS:
            out["roof_connections"].append(head)
            return

        # ── Roof tokens (shape, covering, system, connection)
        if head in ROOF_SHAPE_TOKENS:
            out["roof_shape"] = head
            for p in parts[1:]:
                self._classify_roof_token(p, out)
            return
        if head in ROOF_COVERING_TOKENS:
            out["roof_covering"] = head
            return
        if any(head.startswith(pfx) for pfx in ROOF_SYSTEM_PREFIXES) and head not in MATERIAL_L1_TOKENS:
            self._classify_roof_token(head, out)
            for p in parts[1:]:
                self._classify_roof_token(p, out)
            return

        # ── Floor tokens
        if any(head.startswith(pfx) for pfx in FLOOR_PREFIXES) and head not in MATERIAL_L1_TOKENS:
            if out["floor_material"] is None:
                out["floor_material"] = head
            for p in parts[1:]:
                if p in FLOOR_CONN_TOKENS:
                    out["floor_connection"] = p
            return

        # ── Occupancy (L1 + optional L2 suffix)
        if self._is_occupancy(head):
            self._parse_occupancy(head, out)
            return

        # ── Material block
        resolved = MATERIAL_ALIASES.get(head, head)
        if resolved in MATERIAL_L1_TOKENS:
            self._parse_material(resolved, parts[1:], out)
            return

        # ── System block
        if head in SYSTEM_L1_TOKENS:
            self._parse_system(head, parts[1:], out)
            return

        # ── Floating ductility / code level tokens
        self._parse_level_tokens(parts, out)

    def _parse_numeric(self, head: str, parts: List[str], out: Dict[str, Any]) -> None:
        key, _, val = head.partition(":")
        if key in HEIGHT_AG_KEYS:
            if out["height_stories"] is None:
                out["height_stories"] = self._parse_height_val(key, val)
        elif key in YEAR_KEYS:
            if out["year_value"] is None:
                out["year_token_type"] = key
                out["year_value"] = self._parse_year_val(key, val)

    def _parse_height_val(self, key: str, val: str) -> Optional[int]:
        """Return a single integer for height or None for unknown."""
        val = val.strip()
        if val.upper() in ("UNK", "UNKN", "?", ""):
            return None
        # HBET:7-9 or HBET:10+ style (range as text)
        m_range = re.match(r"(\d+)[-–](\d+)", val)
        if m_range:
            return int(m_range.group(2))  # upper bound
        m_plus = re.match(r"(\d+)\+", val)
        if m_plus:
            return int(m_plus.group(1))   # lower bound of open range
        # HBET:upper,lower (GEM standard numeric)
        if "," in val:
            parts = val.split(",")
            try:
                return int(parts[0])      # upper bound
            except ValueError:
                return None
        # Plain integer
        try:
            return int(val)
        except ValueError:
            return None

    def _parse_year_val(self, key: str, val: str) -> Optional[int]:
        val = val.strip()
        if "," in val:                    # YBET:upper,lower
            parts = val.split(",")
            try:
                a, b = int(parts[0]), int(parts[1])
                return (a + b) // 2       # midpoint
            except ValueError:
                return None
        try:
            return int(val)
        except ValueError:
            return None

    @staticmethod
    def _height_bin(h: Optional[int]) -> Optional[str]:
        if h is None:
            return None
        if 1 <= h <= 3:
            return "L"
        if 4 <= h <= 7:
            return "M"
        if h >= 8:
            return "H"
        return None

    def _is_occupancy(self, token: str) -> bool:
        if token in OCCUPANCY_L1_TOKENS:
            return True
        # L2 occupancy tokens start with an L1 prefix + digits/letters
        for pfx in OCCUPANCY_L1_TOKENS:
            if token.startswith(pfx) and len(token) > len(pfx):
                return True
        return False

    def _parse_occupancy(self, token: str, out: Dict[str, Any]) -> None:
        for pfx in sorted(OCCUPANCY_L1_TOKENS, key=len, reverse=True):
            if token.startswith(pfx):
                out["occupancy"] = pfx
                if len(token) > len(pfx):
                    out["occupancy_detail"] = token
                else:
                    out["occupancy_detail"] = None
                return
        out["occupancy"] = token

    def _parse_material(self, token: str, rest: List[str], out: Dict[str, Any]) -> None:
        if out["material"] is None:
            out["material"] = token
        out["material_all"].append(token)

        for tok in rest:
            tok = MATERIAL_ALIASES.get(tok, tok)
            if tok in MASONRY_UNIT_TOKENS:
                out["material_L2"].append(tok)
            elif tok in MASONRY_REINF_TOKENS:
                out["material_L2"].append(tok)
            elif tok in MORTAR_TOKENS or tok in STONE_TYPE_TOKENS:
                out["material_L3"].append(tok)
            elif tok in DUCTILITY_TOKENS:
                self._set_ductility(tok, out)
            elif tok in CODE_LEVEL_TOKENS:
                self._set_code_level(tok, out)
            elif tok in MATERIAL_L1_TOKENS:
                # Secondary material (e.g. CR+PC — precast)
                out["material_L2"].append(tok)
                out["material_all"].append(tok)

    def _parse_system(self, token: str, rest: List[str], out: Dict[str, Any]) -> None:
        if out["system"] is None:
            out["system"] = token
        out["system_L2"].extend(rest)
        self._parse_level_tokens(rest, out)

    def _parse_level_tokens(self, tokens: List[str], out: Dict[str, Any]) -> None:
        for tok in tokens:
            if tok in CODE_LEVEL_TOKENS:
                self._set_code_level(tok, out)
            elif tok in DUCTILITY_TOKENS:
                self._set_ductility(tok, out)

    def _set_code_level(self, tok: str, out: Dict[str, Any]) -> None:
        if out["code_level"] is None:
            out["code_level"] = tok

    def _set_ductility(self, tok: str, out: Dict[str, Any]) -> None:
        if out["ductility_token"] is None:
            out["ductility_token"] = tok

    def _parse_irregularity(self, tokens: List[str], out: Dict[str, Any]) -> None:
        for tok in tokens:
            if tok in IRREG_L3_TOKENS:
                # Determine if it belongs to plan or vertical irregularity context
                # by checking surrounding L2 tokens — simplified: assign by token type
                if tok in ("TOR", "REC", "IRHO"):
                    out["irregularity_plan_types"].append(tok)
                elif tok in ("SOS", "CRW", "SHC", "POP", "SET", "CHV", "IRVO"):
                    out["irregularity_vert_types"].append(tok)

    def _classify_roof_token(self, tok: str, out: Dict[str, Any]) -> None:
        if tok in ROOF_COVERING_TOKENS:
            out["roof_covering"] = tok
        elif tok in ROOF_CONN_TOKENS:
            out["roof_connections"].append(tok)
        elif any(tok.startswith(pfx) for pfx in ("RM","RE","RC","RME","RWO","RFA","R99","RO")):
            # Roof system material token
            if out["roof_system_material"] is None:
                out["roof_system_material"] = tok

    def _resolve_erd(self, out: Dict[str, Any]) -> None:
        code = out["code_level"]
        duct = out["ductility_token"]
        key = (code, duct)
        info = (DUCTILITY_MAP.get(key)
                or DUCTILITY_MAP.get((code, None))
                or DUCTILITY_MAP.get((None, duct))
                or DUCTILITY_MAP.get((None, None)))
        out["erd"]       = info["erd"]
        out["erd_score"] = info["erd_score"]


class _RuleEngine:
    """Applies EMS_TYPE_RULES to parsed features and returns EMS candidates."""

    def apply(self, parsed: Dict[str, Any]) -> Tuple[List[EmsCandidate], Dict[str, Any]]:
        warnings: List[str] = []
        rule_trace: List[str] = []

        # Determine family first (family-assignment rules have priority < 20)
        family = None
        for rule in sorted(EMS_TYPE_RULES, key=lambda r: r.get("priority", 999)):
            then = rule.get("then", {})
            if "family" not in then:
                continue
            if self._matches(rule.get("if", {}), parsed, family):
                family = then["family"]
                rule_trace.append(rule["id"])
                break
        parsed = dict(parsed, family=family)

        # Base confidence from completeness rubric
        base_conf = self._base_confidence(parsed)

        candidates: List[EmsCandidate] = []
        for rule in sorted(EMS_TYPE_RULES, key=lambda r: r.get("priority", 999)):
            if not self._matches(rule.get("if", {}), parsed, family):
                continue
            rule_id = rule["id"]
            then = rule.get("then", {})
            penalty = float(rule.get("confidence_penalty", 1.0))
            rule_trace.append(rule_id)

            if "family" in then:
                continue  # family rules already processed

            if "ems_type" in then:
                ems_t = then["ems_type"]
                candidates.append(EmsCandidate(
                    ems_type=ems_t, weight=1.0,
                    confidence=base_conf * penalty,
                    rule_id=rule_id, rule_trace=list(rule_trace),
                    flags=[]))
                break

            elif "ems_template" in then:
                erd = parsed.get("erd", "L") or "L"
                ems_t = then["ems_template"].replace("{erd}", erd)
                candidates.append(EmsCandidate(
                    ems_type=ems_t, weight=1.0,
                    confidence=base_conf * penalty,
                    rule_id=rule_id, rule_trace=list(rule_trace),
                    flags=[]))
                break

            elif "fallback" in then:
                fb_key = then["fallback"]
                fb = FALLBACK_PRIORS.get(fb_key, [])
                if not fb:
                    warnings.append(f"Fallback key '{fb_key}' not found in FALLBACK_PRIORS.")
                    continue
                total_w = sum(w for _, w in fb)
                for ems_t, w in fb:
                    candidates.append(EmsCandidate(
                        ems_type=ems_t, weight=w / total_w,
                        confidence=base_conf * penalty,
                        rule_id=rule_id, rule_trace=list(rule_trace),
                        flags=["DISTRIBUTED_MAPPING"]))
                break

        if not candidates:
            candidates = [EmsCandidate("M4", 1.0, 0.20, "FAILSAFE", ["FAILSAFE"], ["FAILSAFE"])]
            warnings.append("No rule matched; FAILSAFE applied.")

        return candidates, {"rule_trace": rule_trace, "warnings": warnings, "family": family}

    def _matches(self, cond: Dict[str, Any], parsed: Dict[str, Any], family: Optional[str]) -> bool:
        mat    = parsed.get("material")
        mat_l2 = parsed.get("material_L2", [])
        mat_all= parsed.get("material_all", [])
        system = parsed.get("system")
        sys_l2 = parsed.get("system_L2", [])

        for key, val in cond.items():
            if key == "material_any":
                if not (any(t in set(val) for t in ([mat] if mat else []))
                        or any(t in set(val) for t in mat_l2)
                        or any(t in set(val) for t in mat_all)):
                    return False
            elif key == "material_L2_any":
                if not any(t in set(val) for t in mat_l2):
                    return False
            elif key == "system_any":
                if system not in set(val):
                    return False
            elif key == "family":
                if family != val:
                    return False
            elif key == "missing_any":
                for attr in val:
                    v = parsed.get(attr)
                    if v is None or v == [] or v == "":
                        break
                else:
                    return False
            else:
                return False
        return True

    def _base_confidence(self, parsed: Dict[str, Any]) -> float:
        has_mat  = parsed.get("material") is not None
        has_sys  = parsed.get("system")   is not None
        has_h    = parsed.get("height_bin") is not None
        has_erd  = parsed.get("erd") is not None and parsed.get("ductility_token") is not None
        if has_mat and has_sys and has_h and has_erd:
            return CONFIDENCE_RUBRIC["material+system+height+erd"]
        if has_mat and has_sys and has_h:
            return CONFIDENCE_RUBRIC["material+system+height"]
        if has_mat and has_h:
            return CONFIDENCE_RUBRIC["material+height"]
        if has_mat:
            return CONFIDENCE_RUBRIC["material"]
        return CONFIDENCE_RUBRIC["partial"]


class _VcModifierEngine:
    """Applies VC_MODIFIERS to the base VC distribution."""

    def apply(
        self,
        vc_probs_base: Dict[str, float],
        parsed: Dict[str, Any],
        final_ems_type: str,
    ) -> Tuple[Dict[str, float], List[Dict[str, Any]], float]:
        """
        Returns (vc_probs_final, modifiers_applied, cumulative_shift).
        """
        applied: List[Dict[str, Any]] = []
        total_shift = 0.0
        conf_penalty_product = 1.0

        for mod in VC_MODIFIERS:
            if not self._mod_matches(mod.get("if", {}), parsed, final_ems_type):
                continue
            raw_shift   = float(mod.get("shift", 0.0))
            max_contrib = float(mod.get("max_contribution", abs(raw_shift) + 1.0))
            # Cap individual contribution
            contrib = max(-max_contrib, min(max_contrib, raw_shift))
            total_shift += contrib
            conf_penalty_product *= float(mod.get("confidence_penalty", 1.0))
            applied.append({
                "id":                 mod["id"],
                "doc":                mod.get("doc", ""),
                "shift":              contrib,
                "confidence_penalty": mod.get("confidence_penalty", 1.0),
            })

        # Clamp total shift
        total_shift = max(-MAX_CUMULATIVE_SHIFT, min(MAX_CUMULATIVE_SHIFT, total_shift))

        # Determine hard bounds from EMS_VOCAB
        vocab_entry = EMS_VOCAB.get(final_ems_type, {})
        lo_cls = vocab_entry.get("vc_range_min", "A")
        hi_cls = vocab_entry.get("vc_range_max", "F")
        lo_idx = VC_ORDER.index(lo_cls)
        hi_idx = VC_ORDER.index(hi_cls)

        # Apply smooth fractional shift
        vc_final = self._shift_distribution(vc_probs_base, total_shift, lo_idx, hi_idx)

        return vc_final, applied, total_shift

    def _shift_distribution(
        self,
        probs: Dict[str, float],
        shift: float,
        lo_idx: int,
        hi_idx: int,
    ) -> Dict[str, float]:
        """
        Smooth fractional shift of a 6-bin distribution.

        shift > 0 → toward A (index 0, more vulnerable)
        shift < 0 → toward F (index 5, less vulnerable)

        Each unit of shift moves mass one step toward A.
        Fractional shifts interpolate linearly between positions.
        Mass cannot leave [lo_idx, hi_idx] (IMS bounds).
        """
        arr = [probs.get(c, 0.0) for c in VC_ORDER]
        n = len(arr)

        # Direction: positive shift → toward A (lower index)
        direction = 1 if shift > 0 else -1
        steps = abs(shift)
        full_steps = int(steps)
        frac = steps - full_steps

        def _shift_once(a: List[float], d: int) -> List[float]:
            """Shift all mass one full step in direction d (d=+1 → toward A)."""
            new = [0.0] * n
            for i in range(n):
                j = i - d   # source index
                if 0 <= j < n:
                    new[i] += a[j]
                else:
                    # Clamp: mass stays at boundary
                    boundary = 0 if d > 0 else n - 1
                    new[boundary] += a[i]
            return new

        # Apply full integer steps
        for _ in range(full_steps):
            arr = _shift_once(arr, direction)

        # Apply fractional step via linear interpolation
        if frac > 0:
            shifted = _shift_once(arr, direction)
            arr = [arr[i] * (1 - frac) + shifted[i] * frac for i in range(n)]

        # Enforce IMS bounds — zero out mass outside [lo_idx, hi_idx]
        for i in range(n):
            if i < lo_idx or i > hi_idx:
                arr[i] = 0.0

        # Renormalise
        s = sum(arr)
        if s <= 0:
            # Distribute uniformly within bounds as fallback
            arr = [0.0] * n
            for i in range(lo_idx, hi_idx + 1):
                arr[i] = 1.0 / (hi_idx - lo_idx + 1)
        else:
            arr = [v / s for v in arr]

        return {c: arr[i] for i, c in enumerate(VC_ORDER)}

    def _mod_matches(self, cond: Dict[str, Any], parsed: Dict[str, Any], ems_type: str) -> bool:
        """Evaluate all conditions in a modifier rule (AND logic)."""
        for key, val in cond.items():

            # ── Parsed attribute conditions ──────────────────────────────
            if key == "family_is":
                if parsed.get("family") != val:
                    return False

            elif key == "family_in":
                if not val:  # empty list = no constraint
                    pass
                elif parsed.get("family") not in val:
                    return False

            elif key == "material_is":
                if parsed.get("material") != val:
                    return False

            elif key == "material_any":
                mat  = parsed.get("material")
                matl = parsed.get("material_L2", [])
                mata = parsed.get("material_all", [])
                pool = (([mat] if mat else []) + matl + mata)
                if not any(t in set(val) for t in pool):
                    return False

            elif key == "material_L2_any":
                if not any(t in set(val) for t in parsed.get("material_L2", [])):
                    return False

            elif key == "material_L3_any":
                if not any(t in set(val) for t in parsed.get("material_L3", [])):
                    return False

            elif key == "system_is":
                if parsed.get("system") != val:
                    return False

            elif key == "system_any":
                if parsed.get("system") not in set(val):
                    return False

            elif key == "infill_any":
                if not val:
                    pass
                elif not any(t in set(val) for t in parsed.get("infill_material", [])):
                    return False

            elif key == "erd_is":
                if parsed.get("erd") != val:
                    return False

            elif key == "erd_score_below":
                score = parsed.get("erd_score", 0.0)
                if score is None or score >= val:
                    return False

            elif key == "erd_score_above":
                score = parsed.get("erd_score", 0.0)
                if score is None or score < val:
                    return False

            elif key == "ductility_token_in":
                if not val:
                    pass
                elif parsed.get("ductility_token") not in set(val):
                    return False

            elif key == "ductility_token_is":
                if parsed.get("ductility_token") != val:
                    return False

            elif key == "code_level_is":
                if parsed.get("code_level") != val:
                    return False

            elif key == "height_bin_is":
                if parsed.get("height_bin") != val:
                    return False

            elif key == "height_bin_in":
                if parsed.get("height_bin") not in set(val):
                    return False

            elif key == "height_stories_above":
                h = parsed.get("height_stories")
                if h is None or h <= val:
                    return False

            elif key == "year_known":
                has_year = parsed.get("year_value") is not None
                if has_year != val:
                    return False

            elif key == "year_before":
                y = parsed.get("year_value")
                if y is None or y >= val:
                    return False

            elif key == "year_after_eq":
                y = parsed.get("year_value")
                if y is None or y < val:
                    return False

            elif key == "occupancy_L1_is":
                if parsed.get("occupancy") != val:
                    return False

            elif key == "occupancy_detail_in":
                if not val:
                    pass
                elif parsed.get("occupancy_detail") not in set(val):
                    return False

            elif key == "position_in":
                if parsed.get("position") not in set(val):
                    return False

            elif key == "plan_shape_in":
                if not val:
                    pass
                elif parsed.get("plan_shape") not in set(val):
                    return False

            elif key == "irregularity_L1_is":
                if parsed.get("irregularity_L1") != val:
                    return False

            elif key == "irregularity_plan_type_in":
                # Empty list means "no plan type present"
                plan_types = parsed.get("irregularity_plan_types", [])
                if val == []:
                    if plan_types:
                        return False
                elif not any(t in set(val) for t in plan_types):
                    return False

            elif key == "irregularity_vert_type_in":
                vert_types = parsed.get("irregularity_vert_types", [])
                if val == []:
                    if vert_types:
                        return False
                elif not any(t in set(val) for t in vert_types):
                    return False

            elif key == "roof_covering_in":
                if not val:
                    pass
                elif parsed.get("roof_covering") not in set(val):
                    return False

            elif key == "roof_system_in":
                rsm = parsed.get("roof_system_material") or ""
                if not val:
                    pass
                elif not any(rsm == v or rsm.startswith(v) for v in val):
                    return False

            elif key == "floor_material_in":
                fm = parsed.get("floor_material") or ""
                if not val:
                    pass
                elif not any(fm == v or fm.startswith(v) for v in val):
                    return False

            elif key == "floor_conn_is":
                if parsed.get("floor_connection") != val:
                    return False

            elif key == "roof_conn_in":
                if not val:
                    pass
                elif not any(t in set(val) for t in parsed.get("roof_connections", [])):
                    return False

            elif key == "foundation_in":
                if parsed.get("foundation") not in set(val):
                    return False

            elif key == "exterior_wall_any":
                if not val:
                    pass
                elif not any(t in set(val) for t in parsed.get("exterior_walls", [])):
                    return False

            elif key == "ems_type_in":
                if ems_type not in set(val):
                    return False

            # Unknown condition key — silently ignore (forward-compatible)

        return True


class gem2ems:
    """
    Main translation engine.

    Usage:
        eng = gem2ems()
        result = eng.translate("CR/LFINF(MUR+CBH)+CDL+DUL/H:3/IND")
        result.vc_class      # → "C"
        result.vc_class_base # → "C"
        result.vc_class_int  # → 3
    """

    def __init__(self) -> None:
        self._parser        = GemParser()
        self._rule_engine   = _RuleEngine()
        self._modifier_engine = _VcModifierEngine()

        # Build exact override lookup (gem_str → override dict)
        self._exact_overrides: Dict[str, Dict[str, Any]] = {
            ov["gem"]: ov
            for ov in EXACT_OVERRIDES
            if isinstance(ov, dict) and ov.get("gem") and ov.get("ems_type")
        }

    # ── Public API ─────────────────────────────────────────────────────────

    def translate(
        self,
        gem: Union[str, List[str]],
        *,
        include_rule_trace: bool = False,
        top_k_types: int = 3,
    ) -> Union[TranslationResult, List[TranslationResult]]:
        if isinstance(gem, str):
            return self.translate_one(gem, include_rule_trace=include_rule_trace,
                                      top_k_types=top_k_types)
        return [self.translate_one(s, include_rule_trace=include_rule_trace,
                                   top_k_types=top_k_types) for s in gem]

    def translate_one(
        self,
        gem_str: str,
        *,
        include_rule_trace: bool = False,
        top_k_types: int = 3,
    ) -> TranslationResult:

        warnings_list: List[str] = []
        gem_str_clean = gem_str.strip()

        # ── Check exact override ────────────────────────────────────────
        ov = self._exact_overrides.get(gem_str_clean)
        if ov is not None:
            return self._apply_exact_override(ov, gem_str_clean, include_rule_trace)

        # ── Parse ───────────────────────────────────────────────────────
        parsed = self._parser.parse(gem_str_clean)

        # ── Apply EMS type rules ────────────────────────────────────────
        candidates, dbg = self._rule_engine.apply(parsed)
        warnings_list.extend(dbg.get("warnings", []))
        parsed["family"] = dbg.get("family")

        # ── Validate EMS types against vocab ───────────────────────────
        valid: List[EmsCandidate] = []
        for c in candidates:
            if c.ems_type in EMS_VOCAB:
                valid.append(c)
            else:
                warnings_list.append(
                    f"EMS type '{c.ems_type}' not in EMS_VOCAB; replaced with M4.")
                valid.append(EmsCandidate(
                    "M4", c.weight, min(c.confidence, 0.30),
                    c.rule_id, c.rule_trace, c.flags + ["EMS_NOT_IN_VOCAB"]))

        # ── Normalise EMS weights ───────────────────────────────────────
        ws = _normalise_list([c.weight for c in valid])
        for c, w in zip(valid, ws):
            c.weight = w

        # ── Build base VC distribution ──────────────────────────────────
        vc_base = {k: 0.0 for k in VC_ORDER}
        for c in valid:
            pri = EMS_VOCAB[c.ems_type]["vc_prior"]
            for vc, p in pri.items():
                vc_base[vc] += c.weight * p
        vc_base = _normalise(vc_base)

        # ── Best EMS type (for modifiers) ───────────────────────────────
        best = max(valid, key=lambda c: c.weight)

        # ── Apply VC modifiers ──────────────────────────────────────────
        vc_final, mods_applied, cumul_shift = self._modifier_engine.apply(
            vc_base, parsed, best.ems_type)

        # ── Entropy & confidence ────────────────────────────────────────
        ems_entropy  = _entropy([c.weight for c in valid])
        vc_ent_base  = _entropy([vc_base[c] for c in VC_ORDER])
        vc_ent_final = _entropy([vc_final[c] for c in VC_ORDER])

        conf_map  = sum(c.weight * c.confidence for c in valid)
        n_cands   = max(len(valid), 2)
        H_norm    = ems_entropy / math.log(n_cands)
        mod_conf  = 1.0
        for m in mods_applied:
            mod_conf *= m["confidence_penalty"]
        conf_final = max(0.0, min(1.0, conf_map * (1.0 - ENTROPY_PENALTY_ALPHA * H_norm) * mod_conf))

        # ── VC class predictions ────────────────────────────────────────
        vc_mode_base  = _vc_mode(vc_base)
        vc_mode_final = _vc_mode(vc_final)
        cr_base_lo, cr_base_hi   = _vc_credible_range(vc_base)
        cr_final_lo, cr_final_hi = _vc_credible_range(vc_final)

        # ── Missing features ────────────────────────────────────────────
        missing: List[str] = []
        if parsed.get("material")    is None:    missing.append("material")
        if parsed.get("system")      is None:    missing.append("system")
        if parsed.get("height_bin")  is None:    missing.append("height")
        if parsed.get("ductility_token") is None: missing.append("ductility")

        # ── Flags ───────────────────────────────────────────────────────
        flags: List[str] = []
        if any("DISTRIBUTED_MAPPING" in c.flags for c in valid):
            flags.append("ONE_TO_MANY_MAPPING")
        if parsed.get("ductility_token") is None:
            flags.append("ERD_DEFAULTED_TO_L")
        if parsed.get("system") is None:
            flags.append("SYSTEM_MISSING")
        if parsed.get("height_bin") is None:
            flags.append("HEIGHT_MISSING")
        if mods_applied:
            flags.append("VC_MODIFIER_APPLIED")

        # ── Build candidate output list ─────────────────────────────────
        sorted_c = sorted(valid, key=lambda c: c.weight, reverse=True)
        out_cands: List[Dict[str, Any]] = []
        for c in sorted_c[:max(1, top_k_types)]:
            d = {
                "ems_type":   c.ems_type,
                "weight":     round(c.weight, 4),
                "confidence": round(c.confidence, 4),
                "rule_id":    c.rule_id,
                "flags":      c.flags,
            }
            if include_rule_trace:
                d["rule_trace"] = c.rule_trace
            out_cands.append(d)

        # ── Assemble result ─────────────────────────────────────────────
        return TranslationResult(
            gem_str    = gem_str_clean,
            parsed     = {
                # Original v1 keys — unchanged
                "material":         parsed.get("material"),
                "material_L2":      parsed.get("material_L2"),
                "system":           parsed.get("system"),
                "system_L2":        parsed.get("system_L2"),
                "erd":              parsed.get("erd"),
                "height_stories":   parsed.get("height_stories"),
                "height_bin":       parsed.get("height_bin"),
                "year_token":       (f"{parsed.get('year_token_type')}:{parsed.get('year_value')}"
                                     if parsed.get("year_value") else None),
                "irregularity":     parsed.get("irregularity_L1"),
                # New v3 keys
                "material_L3":      parsed.get("material_L3"),
                "material_all":     parsed.get("material_all"),
                "infill_material":  parsed.get("infill_material"),
                "code_level":       parsed.get("code_level"),
                "ductility_token":  parsed.get("ductility_token"),
                "erd_score":        parsed.get("erd_score"),
                "year_value":       parsed.get("year_value"),
                "year_token_type":  parsed.get("year_token_type"),
                "occupancy":        parsed.get("occupancy"),
                "occupancy_detail": parsed.get("occupancy_detail"),
                "directions":       parsed.get("directions"),
                "position":         parsed.get("position"),
                "plan_shape":       parsed.get("plan_shape"),
                "irregularity_L1":  parsed.get("irregularity_L1"),
                "irregularity_plan_types": parsed.get("irregularity_plan_types"),
                "irregularity_vert_types": parsed.get("irregularity_vert_types"),
                "exterior_walls":   parsed.get("exterior_walls"),
                "roof_shape":       parsed.get("roof_shape"),
                "roof_covering":    parsed.get("roof_covering"),
                "roof_system_material": parsed.get("roof_system_material"),
                "roof_connections": parsed.get("roof_connections"),
                "floor_material":   parsed.get("floor_material"),
                "floor_connection": parsed.get("floor_connection"),
                "foundation":       parsed.get("foundation"),
                "family":           parsed.get("family"),
            },
            ems_candidates = out_cands,
            vc_probs       = {k: round(vc_final[k], 4) for k in VC_ORDER},
            vc_probs_base  = {k: round(vc_base[k],  4) for k in VC_ORDER},
            summary        = {
                "best_ems_type":             best.ems_type,
                "best_ems_weight":           round(best.weight, 4),
                "best_vc_mode":              vc_mode_final,   # backward-compatible
                "best_vc_mode_base":         vc_mode_base,
                "best_vc_mode_final":        vc_mode_final,
                "vc_credible_range_80":      f"{cr_final_lo}-{cr_final_hi}",
                "vc_credible_range_80_base": f"{cr_base_lo}-{cr_base_hi}",
                "exact_override":            False,
                "n_modifiers_fired":         len(mods_applied),
                "cumulative_shift":          round(cumul_shift, 3),
            },
            uncertainty    = {
                "missing_features":          missing,
                "ems_entropy":               round(ems_entropy, 4),
                "vc_entropy":                round(vc_ent_final, 4),
                "vc_entropy_base":           round(vc_ent_base,  4),
                "top1_margin":               round(sorted_c[0].weight - sorted_c[1].weight, 4)
                                             if len(sorted_c) > 1 else 1.0,
                "modifier_confidence_penalty": round(mod_conf, 4),
                "flags":                     flags,
            },
            confidence             = round(conf_final, 4),
            warnings               = warnings_list,
            vc_class               = vc_mode_final,
            vc_class_int           = VC_INT[vc_mode_final],
            vc_class_base          = vc_mode_base,
            vc_class_base_int      = VC_INT[vc_mode_base],
            vc_modifiers_applied   = mods_applied,
        )

    def _apply_exact_override(
        self,
        ov: Dict[str, Any],
        gem_str: str,
        include_rule_trace: bool,
    ) -> TranslationResult:
        parsed = self._parser.parse(gem_str)
        ems_t  = ov["ems_type"]
        conf   = float(ov.get("confidence", 0.99))
        vocab  = EMS_VOCAB.get(ems_t, {})
        prior  = vocab.get("vc_prior", {c: 1/6 for c in VC_ORDER})
        prior  = _normalise(prior)

        # Optional forced VC class
        forced_vc = ov.get("vc_class")
        if forced_vc and forced_vc in VC_ORDER:
            vc_final = {c: (1.0 if c == forced_vc else 0.0) for c in VC_ORDER}
        else:
            vc_final = dict(prior)
        vc_mode = _vc_mode(vc_final)
        cr_lo, cr_hi = _vc_credible_range(vc_final)

        return TranslationResult(
            gem_str   = gem_str,
            parsed    = {k: parsed.get(k) for k in [
                "material","material_L2","system","system_L2","erd",
                "height_stories","height_bin","year_value","irregularity_L1","family"]},
            ems_candidates = [{"ems_type": ems_t, "weight": 1.0,
                                "confidence": conf, "rule_id": "EXACT_OVERRIDE", "flags": ["EXACT_OVERRIDE"]}],
            vc_probs       = {k: round(vc_final[k], 4) for k in VC_ORDER},
            vc_probs_base  = {k: round(prior[k],    4) for k in VC_ORDER},
            summary        = {
                "best_ems_type":             ems_t,
                "best_ems_weight":           1.0,
                "best_vc_mode":              vc_mode,
                "best_vc_mode_base":         _vc_mode(prior),
                "best_vc_mode_final":        vc_mode,
                "vc_credible_range_80":      f"{cr_lo}-{cr_hi}",
                "vc_credible_range_80_base": f"{cr_lo}-{cr_hi}",
                "exact_override":            True,
                "n_modifiers_fired":         0,
                "cumulative_shift":          0.0,
            },
            uncertainty    = {
                "missing_features":          [],
                "ems_entropy":               0.0,
                "vc_entropy":                round(_entropy(list(vc_final.values())), 4),
                "vc_entropy_base":           round(_entropy(list(prior.values())), 4),
                "top1_margin":               1.0,
                "modifier_confidence_penalty": 1.0,
                "flags":                     ["EXACT_OVERRIDE"],
            },
            confidence             = conf,
            warnings               = [],
            vc_class               = vc_mode,
            vc_class_int           = VC_INT[vc_mode],
            vc_class_base          = _vc_mode(prior),
            vc_class_base_int      = VC_INT[_vc_mode(prior)],
            vc_modifiers_applied   = [],
        )

    # ── Backward-compatible aliases ────────────────────────────────────────
    def translate_many(self, gem_list: List[str], **kwargs) -> List[TranslationResult]:
        return [self.translate_one(s, **kwargs) for s in gem_list]


# Backward-compatible class alias (v1 name)
TranslatorEngine = gem2ems


# ═══════════════════════════════════════════════════════════════════════════════
#  ZONE C — UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def to_dataframe(results: List[TranslationResult]):
    """Convert a list of TranslationResult objects to a pandas DataFrame."""
    import pandas as pd
    rows = []
    for r in results:
        row = {
            # Original v1 columns — unchanged
            "gem_str":           r.gem_str,
            "best_ems_type":     r.summary["best_ems_type"],
            "best_ems_weight":   r.summary["best_ems_weight"],
            "best_vc_mode":      r.summary["best_vc_mode"],
            "vc_range_80":       r.summary["vc_credible_range_80"],
            "confidence":        r.confidence,
            "ems_entropy":       r.uncertainty["ems_entropy"],
            "vc_entropy":        r.uncertainty["vc_entropy"],
            "missing_features":  ",".join(r.uncertainty["missing_features"]),
            # New columns
            "vc_class":          r.vc_class,
            "vc_class_int":      r.vc_class_int,
            "vc_class_base":     r.vc_class_base,
            "vc_class_base_int": r.vc_class_base_int,
            "vc_probs_A":        r.vc_probs.get("A", 0.0),
            "vc_probs_B":        r.vc_probs.get("B", 0.0),
            "vc_probs_C":        r.vc_probs.get("C", 0.0),
            "vc_probs_D":        r.vc_probs.get("D", 0.0),
            "vc_probs_E":        r.vc_probs.get("E", 0.0),
            "vc_probs_F":        r.vc_probs.get("F", 0.0),
            "vc_probs_base_A":   r.vc_probs_base.get("A", 0.0),
            "vc_probs_base_B":   r.vc_probs_base.get("B", 0.0),
            "vc_probs_base_C":   r.vc_probs_base.get("C", 0.0),
            "vc_probs_base_D":   r.vc_probs_base.get("D", 0.0),
            "vc_probs_base_E":   r.vc_probs_base.get("E", 0.0),
            "vc_probs_base_F":   r.vc_probs_base.get("F", 0.0),
            "vc_range_80_base":  r.summary["vc_credible_range_80_base"],
            "vc_entropy_base":   r.uncertainty["vc_entropy_base"],
            "n_modifiers_fired": r.summary["n_modifiers_fired"],
            "cumulative_shift":  r.summary["cumulative_shift"],
            "mod_conf_penalty":  r.uncertainty["modifier_confidence_penalty"],
            "flags":             "|".join(r.uncertainty["flags"]),
            # Parsed key fields
            "material":          r.parsed.get("material"),
            "system":            r.parsed.get("system"),
            "erd":               r.parsed.get("erd"),
            "height_bin":        r.parsed.get("height_bin"),
            "occupancy":         r.parsed.get("occupancy"),
            "family":            r.parsed.get("family"),
        }
        rows.append(row)
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# Quick smoke-test (run: python gem2ems_engine.py)
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    TEST_STRINGS = [
        "CR/LFINF(MUR+CBH)+CDL+DUL/H:3/IND",
        "CR/LFINF(MUR+CBH)+CDL+DUL/H:UNK/IND",
        "CR+PC/LFM+CDL+DUL/H:1/IND",
        "CR+PC/LFM+CDM+DUM/H:3/IND",
        "CR/LWAL+CDM+DUM/HBET:7-9/IND",
        "MUR+STRUB/LWAL+DNO/H:2/IND",
        "MUR+CBH/LWAL+DNO/H:3/IND",
        "MUR+ADO/LWAL+DNO/H:1/IND",
        "MUR+CLBRS/LWAL+DNO/H:4/IND",
        "S/LFBR+CDL+DUL/H:2/IND",
        "S/LFBR+CDM+DUM/H:5/IND",
        "W/LWAL+CDL+DUM/H:2/IND",
        "W/LFINF(MUR+ADO)+DNO/H:1/IND",
        "MATO/LWAL+DNO/H:2/IND",
        "UNK+CDL+DUM/H:3/IND",
        "UNK/LFM+CDL+DUL/H:4/IND",
    ]

    eng = gem2ems()
    print(f"{'GEM string':<42} {'EMS':>8} {'VC_base':>7} {'VC_final':>8} "
          f"{'shift':>6} {'mods':>4} {'conf':>6}")
    print("-" * 92)
    for s in TEST_STRINGS:
        r = eng.translate_one(s)
        print(f"{s:<42} {r.summary['best_ems_type']:>8} "
              f"{r.vc_class_base:>7} {r.vc_class:>8} "
              f"{r.summary['cumulative_shift']:>+6.2f} "
              f"{r.summary['n_modifiers_fired']:>4} "
              f"{r.confidence:>6.3f}")
        if r.warnings:
            for w in r.warnings:
                print(f"  ⚠  {w}")
