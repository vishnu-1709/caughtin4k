from evaluate import evaluate


def test_every_labelled_sample_matches():
    rows, totals = evaluate()
    assert totals["detected_ok"] == totals["expected"] == totals["verdict_ok"]
    assert totals["false_positives"] == 0 and totals["attack_fp_on_clean"] == 0
    assert all(r["verdict_ok"] for r in rows)
