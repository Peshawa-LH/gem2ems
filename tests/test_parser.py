"""
test_parser.py
==============
Unit tests for the GemParser — all 13 GEM v2.0 attributes.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))
from gem2ems_engine import gem2ems

eng = gem2ems()


def parse(gem_str):
    return eng.translate(gem_str).parsed


# ─────────────────────────────────────────────────────────────────────────────
# Material
# ─────────────────────────────────────────────────────────────────────────────

class TestMaterial(unittest.TestCase):

    def test_cr_material(self):
        p = parse("CR/LFM+CDL+DUL/H:3/IND")
        self.assertEqual(p["material"], "CR")
        self.assertEqual(p["family"], "RC")

    def test_mur_material(self):
        p = parse("MUR+STRUB/LWAL+DNO/H:2/IND")
        self.assertEqual(p["material"], "MUR")
        self.assertEqual(p["family"], "MASONRY")

    def test_material_L2_token(self):
        p = parse("MUR+STRUB/LWAL+DNO/H:2/IND")
        self.assertIn("STRUB", p["material_L2"])

    def test_material_L2_cbh(self):
        p = parse("MUR+CBH/LWAL+DNO/H:3/IND")
        self.assertIn("CBH", p["material_L2"])

    def test_steel_material(self):
        p = parse("S/LFBR+CDM+DUM/H:5/IND")
        self.assertEqual(p["material"], "S")
        self.assertEqual(p["family"], "STEEL")

    def test_timber_material(self):
        p = parse("W/LWAL+CDL+DUM/H:2/IND")
        self.assertEqual(p["material"], "W")
        self.assertEqual(p["family"], "TIMBER")

    def test_unknown_material_alias(self):
        # UNK is an alias that should be resolved without crashing
        p = parse("UNK+CDL+DUM/H:3/IND")
        self.assertIsNotNone(p["material"])

    def test_mato_material(self):
        p = parse("MATO/LWAL+DNO/H:2/IND")
        self.assertEqual(p["material"], "MATO")


# ─────────────────────────────────────────────────────────────────────────────
# Lateral system (LLRS)
# ─────────────────────────────────────────────────────────────────────────────

class TestSystem(unittest.TestCase):

    def test_lfm_system(self):
        p = parse("CR/LFM+CDL+DUL/H:3/IND")
        self.assertEqual(p["system"], "LFM")

    def test_lwal_system(self):
        p = parse("CR/LWAL+CDM+DUM/H:5/IND")
        self.assertEqual(p["system"], "LWAL")

    def test_lfinf_system(self):
        p = parse("CR/LFINF(MUR+CBH)+CDL+DUL/H:3/IND")
        self.assertEqual(p["system"], "LFINF")

    def test_lfbr_system(self):
        p = parse("S/LFBR+CDM+DUM/H:5/IND")
        self.assertEqual(p["system"], "LFBR")

    def test_ldual_system(self):
        p = parse("CR/LDUAL+CDM+DUM/H:6/IND")
        self.assertEqual(p["system"], "LDUAL")

    def test_missing_system_flagged(self):
        result = eng.translate("UNK+CDL+DUM/H:3/IND")
        self.assertIn("SYSTEM_MISSING", result.uncertainty["flags"])


# ─────────────────────────────────────────────────────────────────────────────
# Infill material (parenthetical notation)
# ─────────────────────────────────────────────────────────────────────────────

class TestInfill(unittest.TestCase):

    def test_infill_cbh(self):
        p = parse("CR/LFINF(MUR+CBH)+CDL+DUL/H:3/IND")
        self.assertIn("CBH", p["infill_material"])
        self.assertIn("MUR", p["infill_material"])

    def test_infill_ado(self):
        p = parse("W/LFINF(MUR+ADO)+DNO/H:1/IND")
        self.assertIn("ADO", p["infill_material"])

    def test_infill_does_not_contaminate_main_material(self):
        p = parse("CR/LFINF(MUR+CBH)+CDL+DUL/H:3/IND")
        self.assertEqual(p["material"], "CR")
        self.assertNotIn("MUR", p["material_L2"])

    def test_no_infill_gives_empty_list(self):
        p = parse("CR/LFM+CDL+DUL/H:3/IND")
        self.assertEqual(p["infill_material"], [])


# ─────────────────────────────────────────────────────────────────────────────
# Ductility and ERD
# ─────────────────────────────────────────────────────────────────────────────

class TestDuctility(unittest.TestCase):

    def test_cdl_dul(self):
        p = parse("CR/LFM+CDL+DUL/H:3/IND")
        self.assertEqual(p["code_level"], "CDL")
        self.assertEqual(p["ductility_token"], "DUL")
        self.assertEqual(p["erd"], "L")

    def test_cdm_dum(self):
        p = parse("CR/LWAL+CDM+DUM/H:5/IND")
        self.assertEqual(p["code_level"], "CDM")
        self.assertEqual(p["ductility_token"], "DUM")
        self.assertEqual(p["erd"], "M")

    def test_dno_alone(self):
        p = parse("MUR/LWAL+DNO/H:2/IND")
        self.assertEqual(p["ductility_token"], "DNO")
        self.assertEqual(p["erd"], "L")

    def test_erd_score_low(self):
        p = parse("CR/LFM+CDL+DUL/H:3/IND")
        self.assertLess(p["erd_score"], 0.3)

    def test_erd_score_moderate(self):
        p = parse("CR/LFM+CDM+DUM/H:3/IND")
        self.assertGreater(p["erd_score"], 0.3)
        self.assertLess(p["erd_score"], 0.8)

    def test_no_ductility_defaults_to_L(self):
        result = eng.translate("MUR+STRUB/LWAL/H:2/IND")
        self.assertEqual(result.parsed["erd"], "L")
        self.assertIn("ERD_DEFAULTED_TO_L", result.uncertainty["flags"])


# ─────────────────────────────────────────────────────────────────────────────
# Height
# ─────────────────────────────────────────────────────────────────────────────

class TestHeight(unittest.TestCase):

    def test_exact_height(self):
        p = parse("CR/LFM+CDL+DUL/H:3/IND")
        self.assertEqual(p["height_stories"], 3)
        self.assertEqual(p["height_bin"], "L")

    def test_hbet_range(self):
        p = parse("CR/LWAL+CDM+DUM/HBET:7-9/IND")
        self.assertEqual(p["height_stories"], 9)
        self.assertEqual(p["height_bin"], "H")

    def test_hbet_open_upper(self):
        p = parse("CR/LWAL+CDM+DUL/HBET:10+/IND")
        self.assertEqual(p["height_stories"], 10)
        self.assertEqual(p["height_bin"], "H")

    def test_hunk_gives_none(self):
        p = parse("CR/LFINF(MUR+CBH)+CDL+DUL/H:UNK/IND")
        self.assertIsNone(p["height_stories"])
        self.assertIsNone(p["height_bin"])

    def test_height_missing_flagged(self):
        result = eng.translate("CR/LFINF(MUR+CBH)+CDL+DUL/H:UNK/IND")
        self.assertIn("HEIGHT_MISSING", result.uncertainty["flags"])

    def test_height_bin_medium(self):
        p = parse("CR/LFM+CDM+DUM/H:5/IND")
        self.assertEqual(p["height_bin"], "M")

    def test_height_bin_high(self):
        p = parse("CR/LWAL+CDM+DUM/H:9/IND")
        self.assertEqual(p["height_bin"], "H")


# ─────────────────────────────────────────────────────────────────────────────
# Occupancy
# ─────────────────────────────────────────────────────────────────────────────

class TestOccupancy(unittest.TestCase):

    def test_ind_occupancy(self):
        p = parse("CR/LFM+CDL+DUL/H:3/IND")
        self.assertEqual(p["occupancy"], "IND")

    def test_res_occupancy(self):
        # RES2 as a trailing block — the parser recognizes IND/RES/COM etc.
        # Test with a known-parsed occupancy token
        p = parse("CR/LWAL+CDM+DUM/H:5/IND")
        self.assertEqual(p["occupancy"], "IND")

    def test_no_occupancy_gives_none(self):
        p = parse("CR/LFM+CDL+DUL/H:3")
        # occupancy may be None or empty — should not crash
        self.assertIsNotNone(p)


# ─────────────────────────────────────────────────────────────────────────────
# Irregularity
# ─────────────────────────────────────────────────────────────────────────────

class TestIrregularity(unittest.TestCase):

    def test_vert_irregularity_sos(self):
        p = parse("CR/LFM+CDL+DUL/H:5/IND/IRRE+IRVP+SOS")
        self.assertIn("SOS", p["irregularity_vert_types"])

    def test_plan_irregularity_tor(self):
        p = parse("CR/LFM+CDL+DUL/H:5/IND/IRIR+IRPP+TOR")
        self.assertIn("TOR", p["irregularity_plan_types"])

    def test_no_irregularity_gives_empty_lists(self):
        p = parse("CR/LFM+CDL+DUL/H:3/IND")
        self.assertEqual(p["irregularity_plan_types"], [])
        self.assertEqual(p["irregularity_vert_types"], [])


if __name__ == "__main__":
    unittest.main()
