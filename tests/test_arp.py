from conftest import kinds


def test_arp_spoof_is_attack(run):
    r = run("arp_spoof.pcap")
    spoof = [f for f in r.findings if f.kind == "arp_spoofing"]
    assert len(spoof) == 1
    f = spoof[0]
    assert f.verdict == "attack" and f.confidence == "high"
    assert "192.168.1.1" in f.details["ips"]
    assert f.details["new_mac"] == "dc:a6:32:9f:66:66"
    assert f.evidence_frames and f.fix_steps and f.wireshark_filter


def test_duplicate_ip_is_fault(run):
    r = run("duplicate_ip.pcap")
    assert kinds(r) == ["duplicate_ip"]
    f = r.findings[0]
    assert f.verdict == "fault"
    assert f.details["ips"] == ["192.168.1.50"]
    assert f.indicators_against and not f.indicators_for


def test_clean_has_no_arp_findings(run):
    assert not [k for k in kinds(run("clean.pcap")) if k in ("arp_spoofing", "duplicate_ip", "ip_conflict")]
