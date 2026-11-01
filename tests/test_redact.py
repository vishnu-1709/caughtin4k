import json
import re

from engine.redact import Redactor, redact_result


def test_consistent_masks_and_sentence_boundaries():
    r = Redactor()
    out = r.text("Router 192.168.1.1. MAC dc:a6:32:9f:66:66: again 192.168.1.1 and DC:A6:32:9F:66:66")
    assert out == "Router IP-1. MAC MAC-1: again IP-1 and MAC-1"


def test_result_has_no_addresses_left(run):
    s = json.dumps(redact_result(run("mixed_attack_and_fault.pcap")).to_dict())
    assert not re.search(r"192\.168\.\d+\.\d+", s)
    assert not re.search(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", s)
