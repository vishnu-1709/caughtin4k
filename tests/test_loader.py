import os

import pytest

from engine.analyze import analyze
from engine.loader import CaptureError, validate_file


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_rejects_non_pcap(tmp_path):
    with pytest.raises(CaptureError) as e:
        validate_file(write(tmp_path, "x.pcap", b"<script>alert(1)</script>" * 4), 50)
    assert e.value.code == "not_pcap"


def test_rejects_empty_and_header_only(tmp_path):
    with pytest.raises(CaptureError) as e:
        validate_file(write(tmp_path, "e.pcap", b""), 50)
    assert e.value.code == "empty"
    header = open(os.path.join(os.path.dirname(__file__), "..", "samples", "clean.pcap"), "rb").read(24)
    with pytest.raises(CaptureError) as e:
        analyze(write(tmp_path, "h.pcap", header))
    assert e.value.code == "empty"


def test_rejects_too_big(tmp_path):
    with pytest.raises(CaptureError) as e:
        validate_file(write(tmp_path, "b.pcap", b"\xd4\xc3\xb2\xa1" + b"\0" * 2_000_000), 1)
    assert e.value.code == "too_big"


def test_truncated_file_gives_partial_result(tmp_path):
    data = open(os.path.join(os.path.dirname(__file__), "..", "samples", "clean.pcap"), "rb").read()
    r = analyze(write(tmp_path, "t.pcap", data[: len(data) // 2 + 5]))
    assert r.partial and r.packets_read > 0
    assert any("damaged" in w for w in r.warnings)


def test_packet_cap_returns_partial(tmp_path):
    r = analyze(os.path.join(os.path.dirname(__file__), "..", "samples", "clean.pcap"),
                {"config": {"max_packets": 100}})
    assert r.packets_read == 100 and r.partial
