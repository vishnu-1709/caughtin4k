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


def test_dns_hijack_caused_by_rogue_dhcp(run):
    r = run("rogue_dhcp_dns_hijack.pcap")
    hijack = one(r, "dns_hijack")
    rogue = one(r, "rogue_dhcp")
    assert hijack.verdict == "attack" and hijack.details["from_rogue_dhcp"]
    assert ("github.com", "192.168.1.66") in [tuple(p) for p in hijack.details["private"]]
    assert hijack.incident_id == rogue.incident_id and "rogue DHCP" in hijack.linked_text


def test_slow_handshakes(run):
    f = one(run("slow_handshakes.pcap"), "slow_responses")
    assert f.verdict == "fault" and f.details["server"] == "14.139.160.66"
    assert f.details["slow_median_ms"] > 1000


def test_spoofing_linked_to_packet_loss(run):
    r = run("mixed_attack_and_fault.pcap")
    spoof, loss, nas = one(r, "arp_spoofing"), one(r, "tcp_retransmissions"), one(r, "service_refused")
    assert spoof.incident_id == loss.incident_id != nas.incident_id
    assert "ARP spoofing" in loss.linked_text
    assert len(r.incidents) == 2


def test_mtu_icmp_and_black_hole(run):
    found = [f for f in run("mtu.pcap").findings if f.kind == "mtu_mismatch"]
    assert sorted(f.details["mode"] for f in found) == ["blackhole", "icmp"]
    assert all(f.verdict == "fault" for f in found)
    icmp = next(f for f in found if f.details["mode"] == "icmp")
    assert icmp.details["mtu"] == 1400


def test_harmless_look_alikes_are_not_attacks(run):
    swap = run("router_replacement.pcap").findings
    assert [(f.kind, f.verdict) for f in swap] == [("ip_conflict", "uncertain")]
    assert run("busy_browsing.pcap").findings == []
    assert [(f.kind, f.verdict) for f in run("backup_dhcp.pcap").findings] == [("rogue_dhcp", "fault")]


def test_attack_chain_is_one_multi_step_incident(run):
    r = run("attack_chain.pcap")
    assert {(f.kind, f.verdict) for f in r.findings} == {("port_scan", "attack"), ("arp_spoofing", "attack"),
                                                          ("dns_hijack", "attack")}
    assert len(r.incidents) == 1
    inc = r.incidents[0]
    assert inc.summary.startswith("Multi-step attack") and len(inc.steps) == 3 and inc.severity == "critical"
    spoof = one(r, "arp_spoofing")
    assert spoof.details["relayed_out"] >= 5  # the impostor really forwards traffic (man in the middle)
    assert one(r, "dns_hijack").details["forged_macs"] == ["dc:a6:32:9f:66:66"]


def test_cleartext_credentials_found_and_masked(run):
    found = [f for f in run("cleartext_logins.pcap").findings if f.kind == "cleartext_credentials"]
    assert sorted(f.details["protocol"] for f in found) == ["FTP", "HTTP"]
    users = {u for f in found for u in f.details["users"]}
    assert users == {"s***r", "a***n"}


def test_every_finding_has_severity(run):
    for name in ("mixed_attack_and_fault.pcap", "attack_chain.pcap", "dns_failures.pcap"):
        assert all(f.severity in ("critical", "high", "medium", "low") for f in run(name).findings)
