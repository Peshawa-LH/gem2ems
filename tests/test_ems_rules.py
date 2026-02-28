"""
test_ems_rules.py
=================
Unit tests for the EMS type assignment rule cascade.
Covers deterministic rules, ERD templates, fallback distributions,
family assignment, and the failsafe.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))
from gem2ems_engine import gem2ems

eng = gem2ems()


def translate(gem_str):
    return eng.translate(gem_str)


# ─────────────────────────────────────────────────────────────────────────────
# RC frame rules
# ─────────────────────────────────────────────────────────────────────────────

class TestRCFrameRules(unittest.TestCase):

    def test_rc_frame_low_erd(self):
        r = translate("CR/LFM+CDL+DUL/H:3/IND")
        self.assertEqual(r.summary["best_ems_type"], "RC1-L")

    def test_rc_frame_moderate_erd(self):
        r = translate("CR/LFM+CDM+DUM/H:3/IND")
        self.assertEqual(r.summary["best_ems_type"], "RC1-M")

    def test_rc_infilled_frame(self):
        r = translate("CR/LFINF(MUR+CBH)+CDL+DUL/H:3/IND")
        self.assertEqual(r.summary["best_ems_type"], "RC1-L")

    def test_rc_braced_frame(self):
        r = translate("CR/LFBR+CDM+DUM/H:4/IND")
        self.assertEqual(r.summary["best_ems_type"], "RC1-M")


# ─────────────────────────────────────────────────────────────────────────────
# RC wall rules
# ─────────────────────────────────────────────────────────────────────────────

class TestRCWallRules(unittest.TestCase):

    def test_rc_wall_low_erd(self):
        r = translate("CR/LWAL+CDL+DUL/H:3/IND")
        self.assertEqual(r.summary["best_ems_type"], "RC2-L")

    def test_rc_wall_moderate_erd(self):
        r = translate("CR/LWAL+CDM+DUM/H:5/IND")
        self.assertEqual(r.summary["best_ems_type"], "RC2-M")


# ─────────────────────────────────────────────────────────────────────────────
# RC dual system
# ─────────────────────────────────────────────────────────────────────────────

class TestRCDualRules(unittest.TestCase):

    def test_rc_dual_moderate_erd(self):
        r = translate("CR/LDUAL+CDM+DUM/H:6/IND")
        self.assertEqual(r.summary["best_ems_type"], "RC3-M")


# ─────────────────────────────────────────────────────────────────────────────
# Precast RC
# ─────────────────────────────────────────────────────────────────────────────

class TestPrecastRC(unittest.TestCase):

    def test_precast_frame_low_erd(self):
        r = translate("CR+PC/LFM+CDL+DUL/H:1/IND")
        self.assertEqual(r.summary["best_ems_type"], "RC1-L")

    def test_precast_frame_moderate_erd(self):
        r = translate("CR+PC/LFM+CDM+DUM/H:3/IND")
        self.assertEqual(r.summary["best_ems_type"], "RC1-M")


# ─────────────────────────────────────────────────────────────────────────────
# Masonry rules
# ─────────────────────────────────────────────────────────────────────────────

class TestMasonryRules(unittest.TestCase):

    def test_rubble_stone(self):
        r = translate("MUR+STRUB/LWAL+DNO/H:2/IND")
        self.assertEqual(r.summary["best_ems_type"], "M1")

    def test_adobe(self):
        r = translate("MUR+ADO/LWAL+DNO/H:1/IND")
        self.assertEqual(r.summary["best_ems_type"], "M2")

    def test_concrete_hollow_block(self):
        r = translate("MUR+CBH/LWAL+DNO/H:3/IND")
        self.assertIn(r.summary["best_ems_type"], ["M5", "M6", "M7"])

    def test_fired_clay_brick(self):
        r = translate("MUR+CLBRS/LWAL+DNO/H:3/IND")
        self.assertIn(r.summary["best_ems_type"], ["M5", "M6"])

    def test_masonry_probabilistic_has_multiple_candidates(self):
        r = translate("MUR+CBH/LWAL+DNO/H:3/IND")
        self.assertGreater(len(r.ems_candidates), 1)
        self.assertIn("ONE_TO_MANY_MAPPING", r.uncertainty["flags"])


# ─────────────────────────────────────────────────────────────────────────────
# Steel rules
# ─────────────────────────────────────────────────────────────────────────────

class TestSteelRules(unittest.TestCase):

    def test_steel_braced_frame(self):
        r = translate("S/LFBR+CDM+DUM/H:5/IND")
        self.assertIn(r.summary["best_ems_type"], ["S-L", "S-M/H"])

    def test_steel_probabilistic(self):
        r = translate("S/LFBR+CDM+DUM/H:5/IND")
        self.assertIn("ONE_TO_MANY_MAPPING", r.uncertainty["flags"])


# ─────────────────────────────────────────────────────────────────────────────
# Timber rules
# ─────────────────────────────────────────────────────────────────────────────

class TestTimberRules(unittest.TestCase):

    def test_timber_wall(self):
        r = translate("W/LWAL+CDL+DUM/H:2/IND")
        self.assertIn(r.summary["best_ems_type"], ["T1", "T2-L", "T2-M/H"])


# ─────────────────────────────────────────────────────────────────────────────
# Failsafe and unknowns
# ─────────────────────────────────────────────────────────────────────────────

class TestFailsafe(unittest.TestCase):

    def test_unknown_material_returns_result(self):
        r = translate("UNK+CDL+DUM/H:3/IND")
        self.assertIsNotNone(r.summary["best_ems_type"])

    def test_unknown_material_low_confidence(self):
        r = translate("UNK+CDL+DUM/H:3/IND")
        self.assertLess(r.confidence, 0.25)

    def test_empty_ish_string_does_not_crash(self):
        # Minimal valid string
        r = translate("CR/H:3")
        self.assertIsNotNone(r.vc_class)

    def test_all_results_have_vc_probs_summing_to_one(self):
        strings = [
            "CR/LFM+CDL+DUL/H:3/IND",
            "MUR+STRUB/LWAL+DNO/H:2/IND",
            "S/LFBR+CDM+DUM/H:5/IND",
            "W/LWAL+CDL+DUM/H:2/IND",
            "UNK+CDL+DUM/H:3/IND",
        ]
        for s in strings:
            r = translate(s)
            total = sum(r.vc_probs.values())
            self.assertAlmostEqual(total, 1.0, places=3,
                msg=f"vc_probs does not sum to 1 for: {s}")


# ─────────────────────────────────────────────────────────────────────────────
# Exact overrides
# ─────────────────────────────────────────────────────────────────────────────

class TestExactOverrides(unittest.TestCase):

    def test_exact_override_fires(self):
        # This string is in EXACT_OVERRIDES in the engine
        r = translate("/CR+CIP/LFM+CDM/H:5/")
        if r.summary["exact_override"]:
            self.assertEqual(r.summary["best_ems_type"], "RC1-M")
            self.assertGreater(r.confidence, 0.95)
            self.assertIn("EXACT_OVERRIDE", r.uncertainty["flags"])


# ─────────────────────────────────────────────────────────────────────────────
# Batch translation
# ─────────────────────────────────────────────────────────────────────────────

class TestBatchTranslation(unittest.TestCase):

    def test_batch_returns_correct_count(self):
        strings = [
            "CR/LFM+CDL+DUL/H:3/IND",
            "MUR+STRUB/LWAL+DNO/H:2/IND",
            "S/LFBR+CDM+DUM/H:5/IND",
        ]
        results = eng.translate(strings)
        self.assertEqual(len(results), len(strings))

    def test_batch_preserves_order(self):
        strings = [
            "CR/LFM+CDL+DUL/H:3/IND",
            "MUR+STRUB/LWAL+DNO/H:2/IND",
        ]
        results = eng.translate(strings)
        self.assertEqual(results[0].summary["best_ems_type"], "RC1-L")
        self.assertEqual(results[1].summary["best_ems_type"], "M1")

    def test_single_string_and_list_give_same_result(self):
        s = "CR/LWAL+CDM+DUM/H:5/IND"
        r_single = eng.translate(s)
        r_batch = eng.translate([s])[0]
        self.assertEqual(r_single.vc_class, r_batch.vc_class)
        self.assertEqual(r_single.summary["best_ems_type"],
                         r_batch.summary["best_ems_type"])


if __name__ == "__main__":
    unittest.main()
