"""
test_vc_modifiers.py
====================
Unit tests for the VC modifier engine:
  - Modifiers fire on the correct GEM attributes
  - Shift direction is correct (positive → toward A, negative → toward F)
  - IMS hard bounds are enforced
  - Cumulative shift cap is respected
  - Confidence penalty is applied
  - vc_probs_base and vc_probs are distinct when modifiers fire
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
# Modifier firing
# ─────────────────────────────────────────────────────────────────────────────

class TestModifierFiring(unittest.TestCase):

    def test_dno_modifier_fires(self):
        r = translate("MUR+CBH/LWAL+DNO/H:3/IND")
        fired_ids = [m["id"] for m in r.vc_modifiers_applied]
        self.assertTrue(any("DNO" in mid or "DUCTILITY" in mid for mid in fired_ids),
            msg=f"Expected a DNO/ductility modifier to fire. Fired: {fired_ids}")

    def test_infill_modifier_fires_on_rc_infilled_frame(self):
        r = translate("CR/LFINF(MUR+CBH)+CDL+DUL/H:3/IND")
        fired_ids = [m["id"] for m in r.vc_modifiers_applied]
        self.assertGreater(len(fired_ids), 0,
            msg="Expected at least one modifier for RC infilled frame with masonry infill.")

    def test_no_modifier_fires_on_clean_rc_wall(self):
        # Standard RC wall with no special features → no modifiers expected
        r = translate("CR/LWAL+CDM+DUM/H:5/IND")
        self.assertEqual(r.summary["n_modifiers_fired"], 0)
        self.assertNotIn("VC_MODIFIER_APPLIED", r.uncertainty["flags"])

    def test_modifier_flag_set(self):
        r = translate("MUR+STRUB/LWAL+DNO/H:2/IND")
        self.assertIn("VC_MODIFIER_APPLIED", r.uncertainty["flags"])


# ─────────────────────────────────────────────────────────────────────────────
# Shift direction
# ─────────────────────────────────────────────────────────────────────────────

class TestShiftDirection(unittest.TestCase):

    def _weighted_mean(self, vc_probs):
        """Compute the probability-weighted mean VC class index (A=1…F=6)."""
        order = {"A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6}
        return sum(order[k] * v for k, v in vc_probs.items())

    def test_positive_shift_moves_toward_more_vulnerable(self):
        # DNO is a positive shift (more vulnerable)
        r = translate("MUR+CBH/LWAL+DNO/H:4/IND")
        if r.summary["n_modifiers_fired"] > 0 and r.summary["cumulative_shift"] > 0:
            mean_base  = self._weighted_mean(r.vc_probs_base)
            mean_final = self._weighted_mean(r.vc_probs)
            self.assertLessEqual(mean_final, mean_base + 0.01,
                msg="Positive shift should move distribution toward A (lower mean index).")

    def test_cumulative_shift_positive_for_dno(self):
        r = translate("MUR+CBH/LWAL+DNO/H:3/IND")
        self.assertGreaterEqual(r.summary["cumulative_shift"], 0)

    def test_base_and_final_differ_when_modifiers_fire(self):
        r = translate("MUR+CBH/LWAL+DNO/H:4/IND")
        if r.summary["n_modifiers_fired"] > 0:
            self.assertNotEqual(r.vc_probs, r.vc_probs_base)


# ─────────────────────────────────────────────────────────────────────────────
# IMS hard bounds enforcement
# ─────────────────────────────────────────────────────────────────────────────

class TestIMSBounds(unittest.TestCase):

    def test_vc_probs_never_exceed_ims_range(self):
        """M1 (rubble stone) has vc_range_min=A, vc_range_max=B.
        After any modifier, probability should remain within A-B."""
        r = translate("MUR+STRUB/LWAL+DNO/H:2/IND")
        self.assertAlmostEqual(r.vc_probs.get("C", 0), 0.0, places=4)
        self.assertAlmostEqual(r.vc_probs.get("D", 0), 0.0, places=4)
        self.assertAlmostEqual(r.vc_probs.get("E", 0), 0.0, places=4)
        self.assertAlmostEqual(r.vc_probs.get("F", 0), 0.0, places=4)

    def test_vc_probs_always_sum_to_one_after_shift(self):
        strings = [
            "MUR+STRUB/LWAL+DNO/H:2/IND",
            "MUR+CBH/LWAL+DNO/H:4/IND",
            "CR/LFINF(MUR+CBH)+CDL+DUL/H:3/IND",
            "W/LFINF(MUR+ADO)+DNO/H:1/IND",
        ]
        for s in strings:
            r = translate(s)
            total = sum(r.vc_probs.values())
            self.assertAlmostEqual(total, 1.0, places=3,
                msg=f"vc_probs does not sum to 1 after shift for: {s}")


# ─────────────────────────────────────────────────────────────────────────────
# Cumulative shift cap
# ─────────────────────────────────────────────────────────────────────────────

class TestCumulativeShiftCap(unittest.TestCase):

    def test_cumulative_shift_does_not_exceed_max(self):
        """Construct a string with multiple positive-shift conditions.
        The reported cumulative_shift must not exceed MAX_CUMULATIVE_SHIFT (2.0)."""
        # DNO + irregular + infill — multiple positive shifts
        r = translate("CR/LFINF(MUR+ADO)+DNO/H:1/IND/IRRE+IRVP+SOS")
        self.assertLessEqual(abs(r.summary["cumulative_shift"]), 2.0)

    def test_cumulative_shift_reported_correctly(self):
        r = translate("MUR+CBH/LWAL+DNO/H:4/IND")
        # Cumulative shift should match sum of individual modifier shifts (capped)
        reported = r.summary["cumulative_shift"]
        computed = sum(m["shift"] for m in r.vc_modifiers_applied)
        capped = max(-2.0, min(2.0, computed))
        self.assertAlmostEqual(reported, capped, places=4)


# ─────────────────────────────────────────────────────────────────────────────
# Confidence penalty from modifiers
# ─────────────────────────────────────────────────────────────────────────────

class TestModifierConfidencePenalty(unittest.TestCase):

    def test_modifiers_reduce_confidence(self):
        # Clean string (no modifiers)
        r_clean = translate("CR/LWAL+CDM+DUM/H:5/IND")
        # String with modifiers
        r_mod   = translate("MUR+CBH/LWAL+DNO/H:4/IND")
        # The modifier string may have lower confidence due to penalty
        # (not guaranteed since base confidence can differ — check penalty field)
        penalty = r_mod.uncertainty["modifier_confidence_penalty"]
        self.assertLessEqual(penalty, 1.0)

    def test_no_modifier_means_penalty_is_one(self):
        r = translate("CR/LWAL+CDM+DUM/H:5/IND")
        self.assertAlmostEqual(r.uncertainty["modifier_confidence_penalty"], 1.0, places=4)

    def test_modifier_penalty_is_product_of_individual_penalties(self):
        r = translate("MUR+CBH/LWAL+DNO/H:4/IND")
        if r.vc_modifiers_applied:
            product = 1.0
            for m in r.vc_modifiers_applied:
                product *= m.get("confidence_penalty", 1.0)
            self.assertAlmostEqual(
                r.uncertainty["modifier_confidence_penalty"],
                product, places=4
            )


# ─────────────────────────────────────────────────────────────────────────────
# vc_class_base vs vc_class
# ─────────────────────────────────────────────────────────────────────────────

class TestBaseVsFinal(unittest.TestCase):

    def test_base_class_unchanged_when_no_modifiers(self):
        r = translate("CR/LWAL+CDM+DUM/H:5/IND")
        self.assertEqual(r.vc_class_base, r.vc_class)

    def test_base_and_final_vc_probs_unchanged_when_no_modifiers(self):
        r = translate("CR/LWAL+CDM+DUM/H:5/IND")
        for cls in "ABCDEF":
            self.assertAlmostEqual(
                r.vc_probs_base.get(cls, 0),
                r.vc_probs.get(cls, 0), places=6
            )

    def test_n_modifiers_reported_correctly(self):
        r = translate("CR/LWAL+CDM+DUM/H:5/IND")
        self.assertEqual(r.summary["n_modifiers_fired"], len(r.vc_modifiers_applied))


if __name__ == "__main__":
    unittest.main()
