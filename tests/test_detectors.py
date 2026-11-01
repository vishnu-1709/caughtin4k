"""One test per Tier 1 detector, each on its own generated sample."""
from conftest import kinds


def one(result, kind):
    found = [f for f in result.findings if f.kind == kind]
    assert len(found) == 1, f"expected one {kind}, got {kinds(result)}"
    f = found[0]
    assert f.fix_steps and f.explanation and f.likely_cause and f.wireshark_filter
    assert f.evidence_frames and all(n in result.frames for n in f.evidence_frames)
    return f


def test_port_scan(run):
    f = one(run("port_scan.pcap"), "port_scan")
    assert f.verdict == "attack"
    assert f.details["scanner"] == "192.168.1.66"
    assert set(f.details["open_ports"]) == {22, 80}


def test_service_down_is_fault_and_scan_is_not_service_down(run):
    f = one(run("tcp_resets_service_down.pcap"), "service_refused")
    assert f.verdict == "fault" and f.details["port"] == 445
    assert "service_refused" not in kinds(run("port_scan.pcap"))


def test_retransmissions(run):
    f = one(run("tcp_retransmissions.pcap"), "tcp_retransmissions")
    assert f.verdict == "fault" and f.details["rate"] >= 0.1
    assert "192.168.1.20" in f.hosts


def test_dns_failures(run):
    r = run("dns_failures.pcap")
    assert one(r, "dns_timeout").verdict == "fault"
    assert one(r, "dns_servfail").verdict == "fault"


def test_rogue_dhcp(run):
    f = one(run("rogue_dhcp_dns_hijack.pcap"), "rogue_dhcp")
    assert f.verdict == "attack"
    assert f.details["rogue"] == "192.168.1.66" and f.details["legit"] == "192.168.1.1"


def test_clean_capture_has_no_findings(run):
    assert run("clean.pcap").findings == []
