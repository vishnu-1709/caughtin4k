"""Security behaviour: malicious names stay text, exports are escaped, limits hold, CLI paths are safe."""
import os

import pytest

from cli import main as cli_main
from engine.analyze import analyze_safe
from engine.loader import CaptureError
from engine.report import safe_output_path, to_csv, to_html

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def test_xss_names_are_escaped_in_html_report(run):
    r = run("malicious_xss_dnsname.pcap")
    assert any("<script>" in n for f in r.findings for n in f.details.get("names", []))
    page = to_html(r)
    assert "<script>" not in page and "<img" not in page
    assert "&lt;script&gt;" in page
    assert "Content-Security-Policy" in page


def test_csv_formula_injection_is_neutralised():
    from engine.report import _csv_cell
    assert _csv_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)" and _csv_cell("ok") == "ok"


def test_csv_has_evidence_rows(run):
    assert to_csv(run("port_scan.pcap")).count("\n") > 50


def test_not_a_pcap_and_truncated_samples(run):
    with pytest.raises(CaptureError) as e:
        run("not_a_pcap.pcap")
    assert e.value.code == "not_pcap"
    r = run("broken_truncated.pcap")
    assert r.partial and not r.findings


def test_subprocess_hard_timeout_kills_parser():
    with pytest.raises(CaptureError) as e:
        analyze_safe(os.path.join(SAMPLES, "clean.pcap"), {"config": {"subprocess_timeout": 0}})
    assert e.value.code == "timeout"


def test_subprocess_result_matches(run):
    r = analyze_safe(os.path.join(SAMPLES, "arp_spoof.pcap"))
    assert [f.kind for f in r.findings] == [f.kind for f in run("arp_spoof.pcap").findings]


def test_output_path_traversal_refused(tmp_path):
    with pytest.raises(ValueError):
        safe_output_path("../x.html", (".html",), str(tmp_path))
    with pytest.raises(ValueError):
        safe_output_path("report.sh", (".html",), str(tmp_path))
    assert safe_output_path("r.html", (".html",), str(tmp_path)).endswith("r.html")


@pytest.mark.parametrize("name,code", [("clean.pcap", 0), ("duplicate_ip.pcap", 1), ("port_scan.pcap", 2),
                                       ("not_a_pcap.pcap", 3)])
def test_cli_exit_codes(name, code, capsys):
    assert cli_main([os.path.join(SAMPLES, name), "--no-color"]) == code


def test_passwords_never_leave_the_engine(run):
    from engine.report import to_json
    r = run("cleartext_logins.pcap")
    for text in (to_json(r), to_html(r), to_csv(r)):
        for secret in ("Winter2026!", "admin123", "PASS ", "password="):
            assert secret not in text


def test_malformed_huge_record_is_safe(run):
    r = run("malformed_huge_record.pcap")
    assert r.partial and r.packets_read >= 1


def test_result_has_fingerprint(run):
    import hashlib
    r = run("clean.pcap")
    with open(os.path.join(SAMPLES, "clean.pcap"), "rb") as fh:
        assert r.sha256 == hashlib.sha256(fh.read()).hexdigest()
    assert r.activity and r.conversations and r.meta["tool"].startswith("CaughtIn4K")
